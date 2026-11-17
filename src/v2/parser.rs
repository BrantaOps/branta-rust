//! QR and pasted-text parsing. Infallible: an unrecognized value has no type.

use std::collections::HashMap;

use percent_encoding::percent_decode_str;

use crate::enums::{evm_token_type, DestinationType};
use crate::extensions::{derived_key_type, is_ark, is_bolt11, is_silent_payment};

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct QrDestination {
    pub value: String,
    pub r#type: Option<DestinationType>,
    /// Visible address that participates in the secret-key swap check.
    pub secret_key: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct QrParser {
    pub destinations: Vec<QrDestination>,
    pub on_chain_encryption_text: String,
    pub on_chain_encryption_secret: String,
    pub has_unverifiable_instruction: bool,
    /// Destination types this scan may decrypt.
    /// ERC-681 sets one type from the chain id and token contract.
    /// Bitcoin sets `BitcoinAddress`.
    pub expected_secret_key_types: Vec<DestinationType>,
}

impl QrParser {
    pub fn new(qr_text: &str) -> Self {
        let text = normalize_qr_text(qr_text);
        let mut parser = Self {
            destinations: Vec::new(),
            on_chain_encryption_text: String::new(),
            on_chain_encryption_secret: String::new(),
            has_unverifiable_instruction: false,
            expected_secret_key_types: Vec::new(),
        };

        let Some(scheme) = uri_scheme(&text) else {
            parser.destinations.push(QrDestination {
                r#type: detect_plain_text_type(&text),
                value: text,
                secret_key: false,
            });
            return parser;
        };

        let scheme_lower = scheme.to_ascii_lowercase();
        if scheme_lower == "ethereum" {
            let Some((destination_type, address)) = parse_erc681(&text) else {
                parser.destinations.push(QrDestination {
                    value: text,
                    r#type: None,
                    secret_key: false,
                });
                return parser;
            };
            parser.destinations.push(QrDestination {
                value: address,
                r#type: Some(destination_type),
                secret_key: true,
            });
            parser.expected_secret_key_types = vec![destination_type];
            let query = parse_query(&extract_query(&text));
            parser.on_chain_encryption_text = query.get("branta_id").cloned().unwrap_or_default();
            parser.on_chain_encryption_secret =
                query.get("branta_secret").cloned().unwrap_or_default();
            return parser;
        }

        if scheme_lower != "bitcoin" && scheme_lower != "lightning" {
            parser.destinations.push(QrDestination {
                value: text,
                r#type: None,
                secret_key: false,
            });
            return parser;
        }

        let dest_value = extract_destination(&text);
        let dest_type = if scheme_lower == "bitcoin" {
            Some(DestinationType::BitcoinAddress)
        } else {
            lightning_scheme_type(&dest_value)
        };
        if !dest_value.is_empty()
            && dest_type != Some(DestinationType::BitcoinAddress)
            && derived_key_type(&dest_value).is_none()
        {
            parser.has_unverifiable_instruction = true;
        }
        parser.destinations.push(QrDestination {
            value: dest_value,
            r#type: dest_type,
            secret_key: dest_type == Some(DestinationType::BitcoinAddress),
        });

        let query = parse_query(&extract_query(&text));
        parser.on_chain_encryption_text = query.get("branta_id").cloned().unwrap_or_default();
        parser.on_chain_encryption_secret = query.get("branta_secret").cloned().unwrap_or_default();

        let mut add_bindable = |key: &str, on_chain: bool| {
            let Some(value) = query.get(key) else {
                return;
            };
            let dest_type = if on_chain {
                Some(DestinationType::BitcoinAddress)
            } else {
                detect_plain_text_type(value)
            };
            if !value.is_empty() && !on_chain && derived_key_type(value).is_none() {
                parser.has_unverifiable_instruction = true;
                return;
            }
            parser.destinations.push(QrDestination {
                value: value.clone(),
                r#type: dest_type,
                secret_key: on_chain,
            });
        };

        add_bindable("lightning", false);
        add_bindable("ark", false);
        add_bindable("silent_payment", false);
        add_bindable("bc", true);
        add_bindable("tb", true);
        add_bindable("sp", false);
        if query.contains_key("bolt12") {
            parser.has_unverifiable_instruction = true;
        }
        if query.contains_key("lno") {
            parser.has_unverifiable_instruction = true;
        }
        if query.get("pay").is_some_and(|value| !value.is_empty()) {
            parser.has_unverifiable_instruction = true;
        }
        // Legacy: bare `bolt12` / `lno` values without a bindable type still mark unverifiable
        // via the contains_key checks above; do not push them as destinations.

        if parser.destinations.iter().any(|d| d.secret_key) {
            parser.expected_secret_key_types = vec![DestinationType::BitcoinAddress];
        }
        parser
    }

    pub fn destination(&self) -> Option<&str> {
        self.destinations
            .first()
            .map(|destination| destination.value.as_str())
    }

    pub fn is_on_chain_zk(&self) -> bool {
        !self.on_chain_encryption_text.is_empty() && !self.on_chain_encryption_secret.is_empty()
    }
}

pub(crate) fn detect_plain_text_type(value: &str) -> Option<DestinationType> {
    if is_bolt11(value) {
        return Some(DestinationType::Bolt11);
    }
    if is_ark(value) {
        return Some(DestinationType::ArkAddress);
    }
    if is_silent_payment(value) {
        return Some(DestinationType::SilentPayment);
    }
    let lower = value.to_ascii_lowercase();
    if value.starts_with('1')
        || value.starts_with('3')
        || lower.starts_with("bc1")
        || lower.starts_with("tb1")
        || lower.starts_with("bcrt1")
    {
        return Some(DestinationType::BitcoinAddress);
    }
    None
}

fn lightning_scheme_type(dest: &str) -> Option<DestinationType> {
    if is_bolt11(dest) {
        Some(DestinationType::Bolt11)
    } else {
        None
    }
}

fn normalize_qr_text(qr_text: &str) -> String {
    let value = qr_text.trim().trim_matches(|c: char| (c as u32) <= 0x20);
    value
        .chars()
        .filter(|c| *c != '\t' && *c != '\n' && *c != '\r')
        .collect()
}

fn uri_scheme(text: &str) -> Option<&str> {
    let mut chars = text.chars();
    let first = chars.next()?;
    if !first.is_ascii_alphabetic() {
        return None;
    }
    let mut end = first.len_utf8();
    for c in chars {
        if c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.') {
            end += c.len_utf8();
            continue;
        }
        break;
    }
    if text[end..].starts_with(':') {
        Some(&text[..end])
    } else {
        None
    }
}

fn extract_destination(text: &str) -> String {
    let after = text.split_once(':').map(|(_, after)| after).unwrap_or("");
    after.split('?').next().unwrap_or("").to_string()
}

fn extract_query(text: &str) -> String {
    // A "?" after the "#" belongs to the fragment, not the query.
    let text = text.split('#').next().unwrap_or("");
    let after = text.split_once(':').map(|(_, after)| after).unwrap_or("");
    after
        .split_once('?')
        .map(|(_, query)| query.to_string())
        .unwrap_or_default()
}

/// Path of an `ethereum:` URI, without scheme, query, or fragment.
/// One leading slash is dropped.
fn erc681_path(text: &str) -> &str {
    let after = text.split_once(':').map(|(_, after)| after).unwrap_or("");
    let path = after.split(['?', '#']).next().unwrap_or("");
    path.strip_prefix('/').unwrap_or(path)
}

/// `0x` or `0X` followed by 40 hex digits.
fn is_evm_address(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 42
        && bytes[0] == b'0'
        && (bytes[1] == b'x' || bytes[1] == b'X')
        && bytes[2..].iter().all(u8::is_ascii_hexdigit)
}

/// ERC-681 token transfer. The chain id and contract select one destination type.
/// The deposit address is the `address` query param.
fn parse_erc681(text: &str) -> Option<(DestinationType, String)> {
    let path = erc681_path(text);
    let (contract, rest) = path.split_once('@')?;
    // The contract prefix is a lowercase `0x`, then 40 hex digits.
    let contract_bytes = contract.as_bytes();
    if contract_bytes.len() != 42
        || !contract.starts_with("0x")
        || !contract_bytes[2..].iter().all(u8::is_ascii_hexdigit)
    {
        return None;
    }
    let chain = rest.strip_suffix("/transfer")?;
    if chain.is_empty() || !chain.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let digits = chain.trim_start_matches('0');
    // No supported chain id has more than 15 digits.
    if digits.len() > 15 {
        return None;
    }
    let chain_id: u64 = if digits.is_empty() {
        0
    } else {
        digits.parse().ok()?
    };
    let destination_type = evm_token_type(chain_id, contract)?;
    let query = parse_query(&extract_query(text));
    let address = query.get("address")?;
    if !is_evm_address(address) {
        return None;
    }
    Some((destination_type, address.clone()))
}

fn parse_query(query: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key.is_empty() {
            continue;
        }
        let decoded_key = percent_decode_str(key).decode_utf8_lossy().to_string();
        let decoded_value = percent_decode_str(value).decode_utf8_lossy().to_string();
        let lowered = decoded_key.to_ascii_lowercase();
        map.entry(lowered).or_insert(decoded_value);
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tb1_and_bcrt1_are_bitcoin() {
        assert_eq!(
            QrParser::new("tb1qexample").destinations[0].r#type,
            Some(DestinationType::BitcoinAddress)
        );
        assert_eq!(
            QrParser::new("bcrt1qexample").destinations[0].r#type,
            Some(DestinationType::BitcoinAddress)
        );
    }

    #[test]
    fn control_character_inside_scheme_still_types_the_address() {
        let parser = QrParser::new("bitcoi\tn:bc1qmerchant");
        assert_eq!(parser.destination(), Some("bc1qmerchant"));
        assert_eq!(
            parser.destinations[0].r#type,
            Some(DestinationType::BitcoinAddress)
        );
    }

    #[test]
    fn duplicate_query_key_keeps_the_first_value() {
        let parser =
            QrParser::new("bitcoin:bc1qreal?branta_secret=first&branta_secret=second&branta_id=id");
        assert_eq!(parser.on_chain_encryption_secret, "first");
        assert_eq!(parser.on_chain_encryption_text, "id");
    }

    #[test]
    fn bolt12_lno_and_lnurl_are_unverifiable() {
        assert!(QrParser::new("bitcoin:bc1qmerchant?lno=lno1offer").has_unverifiable_instruction);
        assert!(QrParser::new("lightning:LNURL1DP68GURN8GHJ").has_unverifiable_instruction);
        assert!(QrParser::new("lno1offer").destinations[0].r#type.is_none());
    }

    const BASE_USDC: &str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
    const DEPOSIT: &str = "0x1111111111111111111111111111111111111111";

    #[test]
    fn erc681_transfer_binds_the_deposit_and_one_token() {
        let parser = QrParser::new(&format!(
            "ethereum:{BASE_USDC}@8453/transfer?address={DEPOSIT}&uint256=1000000&branta_id=abc%2Bdef%3D&branta_secret=1234"
        ));
        assert_eq!(parser.destination(), Some(DEPOSIT));
        assert_eq!(parser.destinations.len(), 1);
        assert_eq!(
            parser.destinations[0].r#type,
            Some(DestinationType::UsdcBase)
        );
        assert!(parser.destinations[0].secret_key);
        assert_eq!(
            parser.expected_secret_key_types,
            vec![DestinationType::UsdcBase]
        );
        assert_eq!(parser.on_chain_encryption_text, "abc+def=");
        assert_eq!(parser.on_chain_encryption_secret, "1234");
    }

    #[test]
    fn every_rail_binds_the_deposit_and_one_type() {
        for rail in crate::enums::EVM_TOKEN_RAILS {
            let parser = QrParser::new(&format!(
                "ethereum:{}@{}/transfer?address={DEPOSIT}&branta_id=a&branta_secret=b",
                rail.contract, rail.chain_id
            ));
            let label = format!("{:?}", rail.destination_type);
            assert_eq!(parser.destination(), Some(DEPOSIT), "{label}");
            assert_eq!(
                parser.destinations[0].r#type,
                Some(rail.destination_type),
                "{label}"
            );
            assert_eq!(
                parser.expected_secret_key_types,
                vec![rail.destination_type],
                "{label}"
            );
        }
    }

    #[test]
    fn erc681_contract_matches_case_insensitively() {
        let parser = QrParser::new(&format!(
            "ethereum:{}@8453/transfer?address={DEPOSIT}",
            BASE_USDC.to_ascii_lowercase()
        ));
        assert_eq!(
            parser.destinations[0].r#type,
            Some(DestinationType::UsdcBase)
        );
    }

    #[test]
    fn erc681_uint256_is_not_part_of_the_binding() {
        for amount in ["1", "50000000", "999999999999999999999"] {
            let parser = QrParser::new(&format!(
                "ethereum:{BASE_USDC}@8453/transfer?address={DEPOSIT}&uint256={amount}"
            ));
            assert_eq!(parser.destination(), Some(DEPOSIT), "{amount}");
            assert_eq!(
                parser.destinations[0].r#type,
                Some(DestinationType::UsdcBase),
                "{amount}"
            );
        }
    }

    #[test]
    fn erc681_tolerates_one_leading_slash_and_an_upper_case_scheme() {
        for text in [
            format!("ethereum:/{BASE_USDC}@8453/transfer?address={DEPOSIT}"),
            format!("ETHEREUM:{BASE_USDC}@8453/transfer?address={DEPOSIT}"),
        ] {
            assert_eq!(
                QrParser::new(&text).destinations[0].r#type,
                Some(DestinationType::UsdcBase),
                "{text}"
            );
        }
    }

    #[test]
    fn erc681_accepts_an_upper_case_0x_deposit_prefix() {
        let parser = QrParser::new(&format!(
            "ethereum:{BASE_USDC}@8453/transfer?address=0X{}",
            &DEPOSIT[2..]
        ));
        assert_eq!(
            parser.destinations[0].r#type,
            Some(DestinationType::UsdcBase)
        );
    }

    #[test]
    fn erc681_first_address_param_wins() {
        let parser = QrParser::new(&format!(
            "ethereum:{BASE_USDC}@8453/transfer?address={DEPOSIT}&address=0x{}",
            "f".repeat(40)
        ));
        assert_eq!(parser.destination(), Some(DEPOSIT));
    }

    #[test]
    fn percent_encoded_ampersand_stays_inside_branta_id() {
        let parser = QrParser::new(&format!(
            "ethereum:{BASE_USDC}@8453/transfer?address={DEPOSIT}&branta_id=a%26b&branta_secret=s"
        ));
        assert_eq!(parser.on_chain_encryption_text, "a&b");
        assert_eq!(parser.on_chain_encryption_secret, "s");
    }

    #[test]
    fn erc681_params_in_the_fragment_are_not_read() {
        let parser = QrParser::new(&format!(
            "ethereum:{BASE_USDC}@8453/transfer?address={DEPOSIT}#&branta_id=abc&branta_secret=1234"
        ));
        assert_eq!(
            parser.destinations[0].r#type,
            Some(DestinationType::UsdcBase)
        );
        assert_eq!(parser.on_chain_encryption_text, "");
    }

    #[test]
    fn a_query_after_a_fragment_is_not_read() {
        let parser = QrParser::new(&format!(
            "ethereum:{BASE_USDC}@8453/transfer#x?address={DEPOSIT}&branta_id=a&branta_secret=b"
        ));
        assert!(parser.destinations[0].r#type.is_none());
        assert_eq!(parser.on_chain_encryption_text, "");
        assert!(parser.expected_secret_key_types.is_empty());
    }

    #[test]
    fn a_fragment_after_the_query_is_dropped() {
        let parser = QrParser::new(&format!(
            "ethereum:{BASE_USDC}@8453/transfer?address={DEPOSIT}&branta_id=a&branta_secret=b#address=0x2"
        ));
        assert_eq!(parser.destination(), Some(DEPOSIT));
        assert_eq!(parser.on_chain_encryption_text, "a");
        assert_eq!(parser.on_chain_encryption_secret, "b");
    }

    #[test]
    fn bitcoin_query_after_a_fragment_is_not_read() {
        let parser = QrParser::new("bitcoin:bc1qtest#x?branta_id=a&branta_secret=b");
        assert_eq!(parser.on_chain_encryption_text, "");
        let ok = QrParser::new("bitcoin:bc1qtest?branta_id=a&branta_secret=b#frag");
        assert_eq!(ok.on_chain_encryption_secret, "b");
    }

    #[test]
    fn erc681_chain_id_beyond_15_digits_is_untyped() {
        let parser = QrParser::new(&format!(
            "ethereum:{BASE_USDC}@{}/transfer?address={DEPOSIT}",
            "9".repeat(5000)
        ));
        assert!(parser.destinations[0].r#type.is_none());
    }

    #[test]
    fn erc681_leading_zero_chain_id_still_selects_the_rail() {
        let parser = QrParser::new(&format!(
            "ethereum:{BASE_USDC}@{}8453/transfer?address={DEPOSIT}",
            "0".repeat(4500)
        ));
        assert_eq!(
            parser.destinations[0].r#type,
            Some(DestinationType::UsdcBase)
        );
    }

    #[test]
    fn incomplete_erc681_forms_do_not_bind() {
        let tail = format!("?address={DEPOSIT}&branta_id=abc&branta_secret=1234");
        let forms = [
            // No chain id.
            format!("ethereum:{BASE_USDC}/transfer{tail}"),
            // Payment-request prefix and ENS-style forms.
            format!("ethereum:pay-{BASE_USDC}@8453/transfer{tail}"),
            format!("ethereum:vitalik.eth@8453/transfer{tail}"),
            // // makes the contract an authority, not a path.
            format!("ethereum://{BASE_USDC}@8453/transfer{tail}"),
            // Only transfer is a payment. approve and transferFrom are not.
            format!("ethereum:{BASE_USDC}@8453/approve{tail}"),
            format!("ethereum:{BASE_USDC}@8453/transferFrom{tail}"),
            // Path parameters after the function name.
            format!("ethereum:{BASE_USDC}@8453/transfer;x=1{tail}"),
            // Chain id forms that are not plain digits.
            format!("ethereum:{BASE_USDC}@0x2105/transfer{tail}"),
            format!("ethereum:{BASE_USDC}@-8453/transfer{tail}"),
            format!("ethereum:{BASE_USDC}@+8453/transfer{tail}"),
            format!("ethereum:{BASE_USDC}@/transfer{tail}"),
            // No address, a truncated address, or an ENS recipient.
            format!("ethereum:{BASE_USDC}@8453/transfer?branta_id=abc&branta_secret=1234"),
            format!("ethereum:{BASE_USDC}@8453/transfer?address=0x1234&branta_id=abc&branta_secret=1234"),
            format!("ethereum:{BASE_USDC}@8453/transfer?address=vitalik.eth&branta_id=abc&branta_secret=1234"),
        ];
        for text in forms {
            let parser = QrParser::new(&text);
            assert!(parser.destinations[0].r#type.is_none(), "{text}");
            assert!(parser.expected_secret_key_types.is_empty(), "{text}");
            assert_eq!(parser.on_chain_encryption_text, "", "{text}");
            assert!(!parser.destinations[0].secret_key, "{text}");
        }
    }

    #[test]
    fn unknown_contract_and_wrong_chain_do_not_bind() {
        for text in [
            format!(
                "ethereum:0x{}@8453/transfer?address={DEPOSIT}&branta_id=a&branta_secret=b",
                "2".repeat(40)
            ),
            format!(
                "ethereum:{BASE_USDC}@1/transfer?address={DEPOSIT}&branta_id=a&branta_secret=b"
            ),
        ] {
            let parser = QrParser::new(&text);
            assert!(parser.destinations[0].r#type.is_none(), "{text}");
            assert_eq!(parser.on_chain_encryption_text, "", "{text}");
        }
    }

    #[test]
    fn unparseable_or_non_ascii_input_is_an_untyped_destination() {
        let parser = QrParser::new("ethereum://[bad/transfer");
        assert_eq!(parser.destination(), Some("ethereum://[bad/transfer"));
        assert!(parser.destinations[0].r#type.is_none());
        // Multi-byte text around the separators must not panic on a slice.
        for text in [
            "ethereum:é@8453/transfer?address=é",
            "ethereum:0xé@é/transfer#é?é",
            "ethereum:\u{1F600}@\u{1F600}/transfer",
        ] {
            assert!(
                QrParser::new(text).destinations[0].r#type.is_none(),
                "{text}"
            );
        }
        assert_eq!(QrParser::new("bitcoin://[bad").on_chain_encryption_text, "");
    }

    #[test]
    fn removed_chain_schemes_do_not_bind() {
        for scheme in ["pol", "eth", "bsc", "tron", "ton", "sol"] {
            let text = format!(
                "{scheme}:0x278297528c32eCa01295B0d2135984d3442ec963?value=50&branta_id=abc&branta_secret=1234"
            );
            let parser = QrParser::new(&text);
            assert_eq!(parser.destination(), Some(text.as_str()), "{scheme}");
            assert!(parser.destinations[0].r#type.is_none(), "{scheme}");
            assert!(!parser.destinations[0].secret_key, "{scheme}");
            assert!(parser.expected_secret_key_types.is_empty(), "{scheme}");
            assert!(!parser.is_on_chain_zk(), "{scheme}");
        }
    }

    #[test]
    fn bitcoin_uri_expects_bitcoin_secret_key_family() {
        let parser = QrParser::new("bitcoin:bc1qmerchant?branta_id=enc&branta_secret=sec");
        assert!(parser.destinations[0].secret_key);
        assert_eq!(
            parser.expected_secret_key_types,
            vec![DestinationType::BitcoinAddress]
        );
    }

    #[test]
    fn unrecognized_scheme_is_opaque_text() {
        let parser = QrParser::new("ethereum:0xabc?value=1");
        assert_eq!(parser.destination(), Some("ethereum:0xabc?value=1"));
        assert!(parser.destinations[0].r#type.is_none());
        assert!(!parser.destinations[0].secret_key);
        assert!(parser.expected_secret_key_types.is_empty());
        assert!(!parser.is_on_chain_zk());
    }
}
