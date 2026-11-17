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
    UsdtBase,
    UsdcBase,
    UsdtArbitrum,
    UsdcArbitrum,
}

/// An ERC-681 `ethereum:<contract>@<chainId>/transfer` rail.
pub(crate) struct EvmTokenRail {
    pub chain_id: u64,
    /// Lowercase, so lookup is case-insensitive.
    pub contract: &'static str,
    pub destination_type: DestinationType,
}

/// Chain id plus token contract select one destination type.
pub(crate) const EVM_TOKEN_RAILS: &[EvmTokenRail] = &[
    EvmTokenRail {
        chain_id: 1,
        contract: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
        destination_type: DestinationType::UsdcEthereum,
    },
    EvmTokenRail {
        chain_id: 1,
        contract: "0xdac17f958d2ee523a2206206994597c13d831ec7",
        destination_type: DestinationType::UsdtEthereum,
    },
    EvmTokenRail {
        chain_id: 137,
        contract: "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359",
        destination_type: DestinationType::UsdcPolygon,
    },
    EvmTokenRail {
        chain_id: 137,
        contract: "0xc2132d05d31c914a87c6611c10748aeb04b58e8f",
        destination_type: DestinationType::UsdtPolygon,
    },
    EvmTokenRail {
        chain_id: 8453,
        contract: "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
        destination_type: DestinationType::UsdcBase,
    },
    EvmTokenRail {
        chain_id: 8453,
        contract: "0xfde4c96c8593536e31f229ea8f37b2ada2699bb2",
        destination_type: DestinationType::UsdtBase,
    },
    EvmTokenRail {
        chain_id: 42161,
        contract: "0xaf88d065e77c8cc2239327c5edb3a432268e5831",
        destination_type: DestinationType::UsdcArbitrum,
    },
    EvmTokenRail {
        chain_id: 42161,
        contract: "0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9",
        destination_type: DestinationType::UsdtArbitrum,
    },
    EvmTokenRail {
        chain_id: 56,
        contract: "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d",
        destination_type: DestinationType::UsdcBsc,
    },
    EvmTokenRail {
        chain_id: 56,
        contract: "0x55d398326f99059ff775485246999027b3197955",
        destination_type: DestinationType::UsdtBsc,
    },
];

/// The destination type for a chain id and token contract, if they name a rail.
pub(crate) fn evm_token_type(chain_id: u64, contract: &str) -> Option<DestinationType> {
    let needle = contract.to_ascii_lowercase();
    EVM_TOKEN_RAILS
        .iter()
        .find(|rail| rail.chain_id == chain_id && rail.contract == needle)
        .map(|rail| rail.destination_type)
}

/// Address rails `add_payment` encrypts with one UUID secret.
/// Tron, TON, and Solana are included because `add_payment` still encrypts them.
/// They have no verify URI.
pub(crate) fn is_secret_key_address_type(r#type: DestinationType) -> bool {
    matches!(
        r#type,
        DestinationType::BitcoinAddress
            | DestinationType::UsdtTron
            | DestinationType::UsdtTon
            | DestinationType::UsdtSolana
            | DestinationType::UsdcSolana
    ) || EVM_TOKEN_RAILS
        .iter()
        .any(|rail| rail.destination_type == r#type)
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
            (DestinationType::UsdtBase, "\"usdt_base\""),
            (DestinationType::UsdcBase, "\"usdc_base\""),
            (DestinationType::UsdtArbitrum, "\"usdt_arbitrum\""),
            (DestinationType::UsdcArbitrum, "\"usdc_arbitrum\""),
        ];
        assert_eq!(cases.len(), 18);
        for (variant, expected) in cases {
            let json = serde_json::to_string(&variant).unwrap();
            assert_eq!(json, expected);
            let round_tripped: DestinationType = serde_json::from_str(expected).unwrap();
            assert_eq!(round_tripped, variant);
        }
        assert!(serde_json::from_str::<DestinationType>("\"usdc_ton\"").is_err());
    }

    #[test]
    fn evm_token_rails_cover_five_networks_with_one_type_each() {
        let chains: std::collections::BTreeSet<u64> =
            EVM_TOKEN_RAILS.iter().map(|rail| rail.chain_id).collect();
        assert_eq!(
            chains.into_iter().collect::<Vec<_>>(),
            [1, 56, 137, 8453, 42161]
        );
        assert_eq!(EVM_TOKEN_RAILS.len(), 10);
        let types: std::collections::HashSet<DestinationType> = EVM_TOKEN_RAILS
            .iter()
            .map(|rail| rail.destination_type)
            .collect();
        assert_eq!(types.len(), 10);
        for rail in EVM_TOKEN_RAILS {
            assert_eq!(rail.contract, rail.contract.to_ascii_lowercase());
        }
    }

    #[test]
    fn evm_token_type_selects_by_chain_id_and_contract() {
        let base_usdc = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
        assert_eq!(
            evm_token_type(8453, base_usdc),
            Some(DestinationType::UsdcBase)
        );
        assert_eq!(
            evm_token_type(8453, &base_usdc.to_ascii_lowercase()),
            Some(DestinationType::UsdcBase)
        );
        // Same contract on the wrong chain is not a rail.
        assert_eq!(evm_token_type(1, base_usdc), None);
        // Polygon bridged USDC.e is not the native USDC contract.
        assert_eq!(
            evm_token_type(137, "0x2791bca1f2de4661ed88a30c99a7a9449aa84174"),
            None
        );
        // Arbitrum Nova is not Arbitrum One.
        assert_eq!(
            evm_token_type(42170, "0xaf88d065e77c8cc2239327c5edb3a432268e5831"),
            None
        );
    }

    #[test]
    fn secret_key_helper_covers_bitcoin_evm_rails_and_post_only_types() {
        assert!(is_secret_key_address_type(DestinationType::BitcoinAddress));
        for rail in EVM_TOKEN_RAILS {
            assert!(is_secret_key_address_type(rail.destination_type));
        }
        // Tron, TON, and Solana still encrypt on add_payment. They have no verify URI.
        for post_only in [
            DestinationType::UsdtTron,
            DestinationType::UsdtTon,
            DestinationType::UsdtSolana,
            DestinationType::UsdcSolana,
        ] {
            assert!(is_secret_key_address_type(post_only), "{post_only:?}");
        }
        assert!(!is_secret_key_address_type(DestinationType::Bolt11));
        assert!(!is_secret_key_address_type(DestinationType::ArkAddress));
        assert!(!is_secret_key_address_type(DestinationType::SilentPayment));
    }
}
