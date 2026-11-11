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
}

/// Polygon EVM secret-key rails. A `pol:` URI maps to this family for verify
/// (match-if-any). Token is still the destination type on the payment.
pub const POLYGON_EVM_DESTINATION_TYPES: &[DestinationType] =
    &[DestinationType::UsdtPolygon, DestinationType::UsdcPolygon];

/// Reports whether `r#type` is a Polygon EVM rail.
pub fn is_polygon_evm_destination_type(r#type: DestinationType) -> bool {
    matches!(
        r#type,
        DestinationType::UsdtPolygon | DestinationType::UsdcPolygon
    )
}

/// Address rails encrypted with a random `branta_secret` (not a derived key).
pub fn is_secret_key_address_type(r#type: DestinationType) -> bool {
    r#type == DestinationType::BitcoinAddress || is_polygon_evm_destination_type(r#type)
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
        ];
        for (variant, expected) in cases {
            let json = serde_json::to_string(&variant).unwrap();
            assert_eq!(json, expected);
            let round_tripped: DestinationType = serde_json::from_str(expected).unwrap();
            assert_eq!(round_tripped, variant);
        }
    }

    #[test]
    fn polygon_evm_helpers() {
        assert_eq!(
            POLYGON_EVM_DESTINATION_TYPES,
            &[DestinationType::UsdtPolygon, DestinationType::UsdcPolygon]
        );
        assert!(is_polygon_evm_destination_type(
            DestinationType::UsdtPolygon
        ));
        assert!(is_polygon_evm_destination_type(
            DestinationType::UsdcPolygon
        ));
        assert!(!is_polygon_evm_destination_type(
            DestinationType::BitcoinAddress
        ));
        assert!(is_secret_key_address_type(DestinationType::BitcoinAddress));
        assert!(is_secret_key_address_type(DestinationType::UsdtPolygon));
        assert!(!is_secret_key_address_type(DestinationType::Bolt11));
    }
}
