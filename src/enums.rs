//! Server environment, destination type, and verify status.

use serde::{Deserialize, Serialize};

/// Which Branta server to talk to.
///
/// `None` on a per-call override means "leave the service default". A missing
/// default uses staging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BrantaEnvironment {
    Staging,
    Production,
    Localhost,
}

impl BrantaEnvironment {
    /// The base URL for this environment, with no trailing slash.
    pub fn url(self) -> &'static str {
        match self {
            Self::Staging => "https://staging.guardrail.branta.pro",
            Self::Production => "https://guardrail.branta.pro",
            Self::Localhost => "http://localhost:3000",
        }
    }
}

/// A destination `add_payment` can encrypt.
///
/// Wire format is snake_case and must match every other Branta SDK.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DestinationType {
    BitcoinAddress,
    Bolt11,
    ArkAddress,
    SilentPayment,
    UsdtPolygon,
    UsdcPolygon,
    UsdtEthereum,
    UsdcEthereum,
    UsdtBsc,
    UsdcBsc,
    UsdtTron,
    UsdtTon,
    UsdtSolana,
    UsdcSolana,
}

/// Polygon EVM secret-key rails. A `pol:` URI maps to this family for verify
/// (match-if-any). Token is still the destination type on the payment.
pub(crate) const POLYGON_EVM_DESTINATION_TYPES: &[DestinationType] =
    &[DestinationType::UsdtPolygon, DestinationType::UsdcPolygon];

/// Ethereum secret-key rails (`eth:` URI).
pub(crate) const ETHEREUM_EVM_DESTINATION_TYPES: &[DestinationType] =
    &[DestinationType::UsdtEthereum, DestinationType::UsdcEthereum];

/// BSC secret-key rails (`bsc:` URI).
pub(crate) const BSC_EVM_DESTINATION_TYPES: &[DestinationType] =
    &[DestinationType::UsdtBsc, DestinationType::UsdcBsc];

/// Tron secret-key rails (`tron:` URI).
pub(crate) const TRON_DESTINATION_TYPES: &[DestinationType] = &[DestinationType::UsdtTron];

/// TON secret-key rails (`ton:` URI).
pub(crate) const TON_DESTINATION_TYPES: &[DestinationType] = &[DestinationType::UsdtTon];

/// Solana secret-key rails (`sol:` URI).
pub(crate) const SOLANA_DESTINATION_TYPES: &[DestinationType] =
    &[DestinationType::UsdtSolana, DestinationType::UsdcSolana];

/// URI scheme → secret-key destination family for verify (match-if-any).
/// Token is the destination type on the payment, not the scheme.
pub(crate) const SECRET_KEY_URI_FAMILIES: &[(&str, &[DestinationType])] = &[
    ("pol", POLYGON_EVM_DESTINATION_TYPES),
    ("eth", ETHEREUM_EVM_DESTINATION_TYPES),
    ("bsc", BSC_EVM_DESTINATION_TYPES),
    ("tron", TRON_DESTINATION_TYPES),
    ("ton", TON_DESTINATION_TYPES),
    ("sol", SOLANA_DESTINATION_TYPES),
];

/// The secret-key family for a lowercase URI scheme, if it names one.
pub(crate) fn secret_key_uri_family(scheme: &str) -> Option<&'static [DestinationType]> {
    SECRET_KEY_URI_FAMILIES
        .iter()
        .find(|(name, _)| *name == scheme)
        .map(|(_, family)| *family)
}

/// Address rails encrypted with a random `branta_secret` (not a derived key).
pub(crate) fn is_secret_key_address_type(r#type: DestinationType) -> bool {
    r#type == DestinationType::BitcoinAddress
        || SECRET_KEY_URI_FAMILIES
            .iter()
            .any(|(_, family)| family.contains(&r#type))
}

/// The result of [`crate::BrantaService::verify`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerifyStatus {
    Match,
    Unknown,
    Tampered,
    Incomplete,
}

impl VerifyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Match => "match",
            Self::Unknown => "unknown",
            Self::Tampered => "tampered",
            Self::Incomplete => "incomplete",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_urls_match_reference() {
        assert_eq!(
            BrantaEnvironment::Staging.url(),
            "https://staging.guardrail.branta.pro"
        );
        assert_eq!(
            BrantaEnvironment::Production.url(),
            "https://guardrail.branta.pro"
        );
        assert_eq!(BrantaEnvironment::Localhost.url(), "http://localhost:3000");
    }

    #[test]
    fn destination_type_wire_format_is_exact() {
        let cases = [
            (DestinationType::BitcoinAddress, "\"bitcoin_address\""),
            (DestinationType::Bolt11, "\"bolt11\""),
            (DestinationType::ArkAddress, "\"ark_address\""),
            (DestinationType::SilentPayment, "\"silent_payment\""),
            (DestinationType::UsdtPolygon, "\"usdt_polygon\""),
            (DestinationType::UsdcPolygon, "\"usdc_polygon\""),
            (DestinationType::UsdtEthereum, "\"usdt_ethereum\""),
            (DestinationType::UsdcEthereum, "\"usdc_ethereum\""),
            (DestinationType::UsdtBsc, "\"usdt_bsc\""),
            (DestinationType::UsdcBsc, "\"usdc_bsc\""),
            (DestinationType::UsdtTron, "\"usdt_tron\""),
            (DestinationType::UsdtTon, "\"usdt_ton\""),
            (DestinationType::UsdtSolana, "\"usdt_solana\""),
            (DestinationType::UsdcSolana, "\"usdc_solana\""),
        ];
        assert_eq!(cases.len(), 14);
        for (variant, expected) in cases {
            let json = serde_json::to_string(&variant).unwrap();
            assert_eq!(json, expected);
            let round_tripped: DestinationType = serde_json::from_str(expected).unwrap();
            assert_eq!(round_tripped, variant);
        }
        assert!(serde_json::from_str::<DestinationType>("\"usdc_ton\"").is_err());
    }

    #[test]
    fn secret_key_uri_families_cover_all_stable_rails() {
        let schemes: Vec<&str> = SECRET_KEY_URI_FAMILIES.iter().map(|(n, _)| *n).collect();
        assert_eq!(schemes, ["pol", "eth", "bsc", "tron", "ton", "sol"]);
        assert_eq!(
            secret_key_uri_family("eth"),
            Some(&[DestinationType::UsdtEthereum, DestinationType::UsdcEthereum][..])
        );
        assert_eq!(
            secret_key_uri_family("tron"),
            Some(&[DestinationType::UsdtTron][..])
        );
        assert_eq!(
            secret_key_uri_family("sol"),
            Some(&[DestinationType::UsdtSolana, DestinationType::UsdcSolana][..])
        );
        assert_eq!(secret_key_uri_family("bitcoin"), None);
        assert!(is_secret_key_address_type(DestinationType::BitcoinAddress));
        assert!(is_secret_key_address_type(DestinationType::UsdtPolygon));
        assert!(!is_secret_key_address_type(DestinationType::Bolt11));
        for (_, family) in SECRET_KEY_URI_FAMILIES {
            for t in *family {
                assert!(is_secret_key_address_type(*t));
            }
        }
        assert!(!is_secret_key_address_type(DestinationType::ArkAddress));
        assert!(!is_secret_key_address_type(DestinationType::SilentPayment));
    }
}
