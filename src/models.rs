//! Wire models exchanged with the Branta API.

use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde::ser::{SerializeMap, Serializer};
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::enums::{DestinationType, VerifyStatus};

/// A payment destination.
///
/// `id` is sent as `zk_id`. Serialization always sends `zk: true`.
/// On a GET, `zk: true` attempts decrypt. A missing or false `zk` skips decrypt.
#[derive(Debug, Clone, PartialEq)]
pub struct Destination {
    pub value: String,
    pub is_primary: bool,
    pub is_encrypted: bool,
    pub r#type: Option<DestinationType>,
    pub id: Option<String>,
    pub encrypted_dek: Option<String>,
}

impl Destination {
    pub fn new(value: impl Into<String>, r#type: Option<DestinationType>) -> Self {
        Self {
            value: value.into(),
            is_primary: false,
            is_encrypted: false,
            r#type,
            id: None,
            encrypted_dek: None,
        }
    }
}

impl Serialize for Destination {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut len = 3;
        if self.r#type.is_some() {
            len += 1;
        }
        if self.id.is_some() {
            len += 1;
        }
        if self.encrypted_dek.is_some() {
            len += 1;
        }
        let mut map = serializer.serialize_map(Some(len))?;
        map.serialize_entry("value", &self.value)?;
        map.serialize_entry("primary", &self.is_primary)?;
        map.serialize_entry("zk", &true)?;
        if let Some(r#type) = self.r#type {
            map.serialize_entry("type", &r#type)?;
        }
        if let Some(id) = &self.id {
            map.serialize_entry("zk_id", id)?;
        }
        if let Some(dek) = &self.encrypted_dek {
            map.serialize_entry("encrypted_dek", dek)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for Destination {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct DestVisitor;
        impl<'de> Visitor<'de> for DestVisitor {
            type Value = Destination;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a destination object")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut value = None;
                let mut is_primary = false;
                let mut zk: Option<bool> = None;
                let mut r#type = None;
                let mut id = None;
                let mut encrypted_dek = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "value" => value = Some(map.next_value()?),
                        "primary" => is_primary = map.next_value().unwrap_or(false),
                        "zk" => zk = map.next_value().ok(),
                        "type" => r#type = map.next_value().ok(),
                        "zk_id" => id = map.next_value().ok(),
                        "encrypted_dek" => encrypted_dek = map.next_value().ok(),
                        _ => {
                            let _ = map.next_value::<de::IgnoredAny>()?;
                        }
                    }
                }
                Ok(Destination {
                    value: value.unwrap_or_default(),
                    is_primary,
                    is_encrypted: zk == Some(true),
                    r#type,
                    id,
                    encrypted_dek,
                })
            }
        }
        deserializer.deserialize_map(DestVisitor)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Platform {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logo_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logo_light_url: Option<String>,
}

fn is_zero(value: &i32) -> bool {
    *value == 0
}

/// A payment exchanged with Guardrail.
///
/// `description` is not a plaintext API field. `add_payment` folds it into
/// encrypted metadata, and `verify` lifts it back after metadata decrypts.
/// `parent_platform` is set by the server and is never sent on a POST.
///
/// `brand` is the payee a shared-key platform tags a payment with. It is the only brand field
/// sent on the wire. `child_platform` is the deprecated old name: it is never serialized. The
/// effective brand is `brand` if set, otherwise `child_platform`. A parsed payload fills `brand`
/// from `brand` or `child_platform` (`brand` wins) and mirrors it into `child_platform`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Payment {
    pub description: Option<String>,
    pub destinations: Vec<Destination>,
    pub created_at: Option<String>,
    pub ttl: i32,
    pub metadata: Option<String>,
    pub platform: Option<String>,
    pub platform_logo_url: Option<String>,
    pub platform_logo_light_url: Option<String>,
    pub parent_platform: Option<Platform>,
    pub brand: Option<Platform>,
    /// Deprecated: use [`Payment::brand`]. Never sent on the wire.
    #[deprecated(note = "Use brand")]
    pub child_platform: Option<Platform>,
    pub is_metadata_decrypted: bool,
}

#[allow(deprecated)]
impl Payment {
    /// `brand` if set, otherwise the deprecated `child_platform`.
    pub(crate) fn effective_brand(&self) -> Option<&Platform> {
        self.brand.as_ref().or(self.child_platform.as_ref())
    }

    /// Writes the effective brand into both `brand` and the deprecated `child_platform`.
    pub(crate) fn normalize_brand(&mut self) {
        let brand = self.effective_brand().cloned();
        self.brand = brand.clone();
        self.child_platform = brand;
    }
}

/// Borrowed wire shape of a POST body. It never carries `child_platform`.
#[derive(Serialize)]
struct PaymentWire<'a> {
    destinations: &'a [Destination],
    #[serde(skip_serializing_if = "Option::is_none")]
    created_at: &'a Option<String>,
    #[serde(skip_serializing_if = "is_zero")]
    ttl: &'a i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    platform: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    platform_logo_url: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    platform_logo_light_url: &'a Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    brand: Option<&'a Platform>,
}

impl Serialize for Payment {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        PaymentWire {
            destinations: &self.destinations,
            created_at: &self.created_at,
            ttl: &self.ttl,
            metadata: &self.metadata,
            platform: &self.platform,
            platform_logo_url: &self.platform_logo_url,
            platform_logo_light_url: &self.platform_logo_light_url,
            brand: self.effective_brand(),
        }
        .serialize(serializer)
    }
}

/// Parsed shape of a payment payload: accepts both `brand` and `child_platform`.
#[derive(Deserialize)]
struct PaymentRaw {
    #[serde(default)]
    destinations: Vec<Destination>,
    #[serde(default)]
    created_at: Option<String>,
    #[serde(default)]
    ttl: i32,
    #[serde(default)]
    metadata: Option<String>,
    #[serde(default)]
    platform: Option<String>,
    #[serde(default)]
    platform_logo_url: Option<String>,
    #[serde(default)]
    platform_logo_light_url: Option<String>,
    #[serde(default)]
    parent_platform: Option<Platform>,
    #[serde(default)]
    brand: Option<Platform>,
    #[serde(default)]
    child_platform: Option<Platform>,
}

#[allow(deprecated)]
impl<'de> Deserialize<'de> for Payment {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = PaymentRaw::deserialize(deserializer)?;
        let brand = raw.brand.or(raw.child_platform);
        Ok(Payment {
            description: None,
            destinations: raw.destinations,
            created_at: raw.created_at,
            ttl: raw.ttl,
            metadata: raw.metadata,
            platform: raw.platform,
            platform_logo_url: raw.platform_logo_url,
            platform_logo_light_url: raw.platform_logo_light_url,
            parent_platform: raw.parent_platform,
            brand: brand.clone(),
            child_platform: brand,
            is_metadata_decrypted: false,
        })
    }
}

/// What [`crate::BrantaService::verify`] returns. `payments` is set only for a match.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifyResult {
    pub status: VerifyStatus,
    pub payments: Vec<Payment>,
    pub verify_url: String,
    /// Decrypted rails that bound the scan on `Match` (the token is on `type`).
    pub matched_destinations: Vec<Destination>,
}

/// The result of [`crate::BrantaService::add_payment`].
#[derive(Debug, Clone, PartialEq)]
pub struct AddPaymentResult {
    pub payment: Payment,
    pub secret: String,
    pub verify_url: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destination_wire_always_sends_zk_true() {
        let destination = Destination {
            value: "abc".into(),
            is_primary: true,
            is_encrypted: false,
            r#type: Some(DestinationType::BitcoinAddress),
            id: Some("zk-1".into()),
            encrypted_dek: Some("dek".into()),
        };
        let json = serde_json::to_value(&destination).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "value": "abc",
                "primary": true,
                "zk": true,
                "type": "bitcoin_address",
                "zk_id": "zk-1",
                "encrypted_dek": "dek",
            })
        );
    }

    #[test]
    fn missing_or_false_zk_skips_decrypt() {
        let missing: Destination = serde_json::from_str(r#"{"value":"abc"}"#).unwrap();
        assert!(!missing.is_encrypted);
        let falsy: Destination = serde_json::from_str(r#"{"value":"abc","zk":false}"#).unwrap();
        assert!(!falsy.is_encrypted);
        let truthy: Destination =
            serde_json::from_str(r#"{"value":"abc","zk":true,"zk_id":"zk-1"}"#).unwrap();
        assert!(truthy.is_encrypted);
        assert_eq!(truthy.id.as_deref(), Some("zk-1"));
    }

    #[test]
    fn payment_omits_description_parent_and_unset_ttl() {
        let payment = Payment {
            description: Some("desc".into()),
            destinations: vec![Destination::new("abc", None)],
            ttl: 0,
            parent_platform: Some(Platform {
                name: Some("Parent".into()),
                ..Platform::default()
            }),
            ..Payment::default()
        };
        let json = serde_json::to_value(&payment).unwrap();
        assert!(json.get("description").is_none());
        assert!(json.get("parent_platform").is_none());
        assert!(json.get("ttl").is_none());
        assert_eq!(json["destinations"][0]["zk"], true);
    }

    #[test]
    fn payment_sends_ttl_when_set() {
        let payment = Payment {
            ttl: 600,
            ..Payment::default()
        };
        let json = serde_json::to_value(&payment).unwrap();
        assert_eq!(json["ttl"], 600);
    }

    fn platform(name: &str) -> Platform {
        Platform {
            name: Some(name.into()),
            logo_url: Some(format!("https://example.com/{name}.png")),
            logo_light_url: Some(format!("https://example.com/{name}-light.png")),
        }
    }

    #[test]
    fn payment_sends_brand_wire_body() {
        let payment = Payment {
            brand: Some(platform("Acme")),
            ..Payment::default()
        };
        let json = serde_json::to_value(&payment).unwrap();
        assert_eq!(
            json["brand"],
            serde_json::json!({
                "name": "Acme",
                "logo_url": "https://example.com/Acme.png",
                "logo_light_url": "https://example.com/Acme-light.png",
            })
        );
        assert!(json.get("child_platform").is_none());
    }

    #[test]
    fn brand_omits_unset_keys() {
        let payment = Payment {
            brand: Some(Platform {
                name: Some("Acme".into()),
                ..Platform::default()
            }),
            ..Payment::default()
        };
        let json = serde_json::to_value(&payment).unwrap();
        assert_eq!(json["brand"], serde_json::json!({ "name": "Acme" }));
    }

    #[test]
    fn payment_without_brand_omits_the_key() {
        let json = serde_json::to_value(Payment::default()).unwrap();
        assert!(json.get("brand").is_none());
        assert!(json.get("child_platform").is_none());
    }

    #[test]
    #[allow(deprecated)]
    fn deprecated_child_platform_alone_serializes_as_brand() {
        let payment = Payment {
            child_platform: Some(platform("Old")),
            ..Payment::default()
        };
        let json = serde_json::to_value(&payment).unwrap();
        assert_eq!(json["brand"]["name"], "Old");
        assert_eq!(json["brand"]["logo_url"], "https://example.com/Old.png");
        assert!(json.get("child_platform").is_none());
    }

    #[test]
    #[allow(deprecated)]
    fn brand_wins_over_child_platform_on_serialize() {
        let payment = Payment {
            brand: Some(platform("New")),
            child_platform: Some(platform("Old")),
            ..Payment::default()
        };
        let json = serde_json::to_value(&payment).unwrap();
        assert_eq!(json["brand"]["name"], "New");
        assert!(json.get("child_platform").is_none());
    }

    #[test]
    #[allow(deprecated)]
    fn parses_brand_and_mirrors_into_child_platform() {
        let payment: Payment =
            serde_json::from_str(r#"{"brand":{"name":"New","logo_url":"https://x/y.png"}}"#)
                .unwrap();
        assert_eq!(payment.brand.as_ref().unwrap().name.as_deref(), Some("New"));
        assert_eq!(payment.brand, payment.child_platform);
    }

    #[test]
    #[allow(deprecated)]
    fn parses_child_platform_into_brand_and_keeps_old_field() {
        let payment: Payment =
            serde_json::from_str(r#"{"child_platform":{"name":"Old"}}"#).unwrap();
        assert_eq!(payment.brand.as_ref().unwrap().name.as_deref(), Some("Old"));
        assert_eq!(payment.brand, payment.child_platform);
    }

    #[test]
    #[allow(deprecated)]
    fn parsing_both_prefers_brand() {
        let payment: Payment =
            serde_json::from_str(r#"{"child_platform":{"name":"Old"},"brand":{"name":"New"}}"#)
                .unwrap();
        assert_eq!(payment.brand.as_ref().unwrap().name.as_deref(), Some("New"));
        assert_eq!(
            payment.child_platform.as_ref().unwrap().name.as_deref(),
            Some("New")
        );
    }

    #[test]
    #[allow(deprecated)]
    fn null_brand_falls_back_to_child_platform() {
        let payment: Payment =
            serde_json::from_str(r#"{"brand":null,"child_platform":{"name":"Old"}}"#).unwrap();
        assert_eq!(payment.brand.as_ref().unwrap().name.as_deref(), Some("Old"));
    }
}
