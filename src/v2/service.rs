//! Encrypt and decrypt around the HTTP client.
//!
//! `verify` returns a status. A swapped address or a derived-key plaintext that
//! is not the scanned value is [`VerifyStatus::Tampered`]. A 404 is
//! [`VerifyStatus::Unknown`]. Any other non-OK response, a network failure /
//! timeout, or a malformed GET body is [`VerifyStatus::Incomplete`]. A logo URL
//! on the wrong origin still returns [`BrantaError::LogoUrlDomainMismatch`].
//!
//! `add_payment` encrypts a copy. A failed post leaves the caller's [`Payment`] plaintext.

use indexmap::IndexMap;
use percent_encoding::utf8_percent_encode;
use uuid::Uuid;

use crate::enums::{is_secret_key_address_type, DestinationType, VerifyStatus};
use crate::error::BrantaError;
use crate::extensions::{derived_key_type, to_normalized_hash, to_url_fragment};
use crate::models::{AddPaymentResult, Destination, Payment, VerifyResult};
use crate::options::BrantaApiOptions;

use super::client::{BrantaClient, BrantaClientTrait, PATH_SEGMENT};
use super::encryption::{AesEncryptionService, AesEncryptionTrait};
use super::parser::QrParser;
use super::secret_generator::{GuidSecretGenerator, SecretGeneratorTrait};

enum LookupFail {
    Tampered,
    Incomplete,
    Other(BrantaError),
}

fn addresses_match(a: &str, b: &str) -> bool {
    fn is_bech32(value: &str) -> bool {
        let lower = value.to_ascii_lowercase();
        lower.starts_with("bc1") || lower.starts_with("tb1") || lower.starts_with("bcrt1")
    }
    let both_evm =
        a.to_ascii_lowercase().starts_with("0x") && b.to_ascii_lowercase().starts_with("0x");
    let case_insensitive = (is_bech32(a) && is_bech32(b)) || both_evm;
    if case_insensitive {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}

/// Every secret-key address in the QR must agree. `None` means the QR has none.
fn uniform_on_chain_address(parser: &QrParser) -> Result<Option<String>, LookupFail> {
    let mut addresses = parser
        .destinations
        .iter()
        .filter(|destination| destination.secret_key && !destination.value.trim().is_empty());
    let Some(first) = addresses.next() else {
        return Ok(None);
    };
    if addresses.any(|destination| !addresses_match(&first.value, &destination.value)) {
        return Err(LookupFail::Tampered);
    }
    Ok(Some(first.value.clone()))
}

fn matched_destinations_from(payments: &[Payment]) -> Vec<Destination> {
    payments
        .iter()
        .flat_map(|payment| payment.destinations.iter())
        .filter(|destination| !destination.is_encrypted)
        .cloned()
        .collect()
}

fn to_verify_result(payments: Vec<Payment>, verify_url: String) -> VerifyResult {
    if payments.is_empty() {
        VerifyResult {
            status: VerifyStatus::Unknown,
            payments,
            verify_url,
            matched_destinations: Vec::new(),
        }
    } else {
        let matched_destinations = matched_destinations_from(&payments);
        VerifyResult {
            status: VerifyStatus::Match,
            payments,
            verify_url,
            matched_destinations,
        }
    }
}

fn status_only(status: VerifyStatus, verify_url: String) -> VerifyResult {
    VerifyResult {
        status,
        payments: Vec::new(),
        verify_url,
        matched_destinations: Vec::new(),
    }
}

fn lookup_error(err: BrantaError) -> LookupFail {
    match err {
        BrantaError::Incomplete => LookupFail::Incomplete,
        other => LookupFail::Other(other),
    }
}

pub struct BrantaService {
    default_options: BrantaApiOptions,
    client: Box<dyn BrantaClientTrait>,
    aes: Box<dyn AesEncryptionTrait>,
    secret_generator: Box<dyn SecretGeneratorTrait>,
}

impl BrantaService {
    /// Production constructor: real HTTP client, real AES-GCM, real UUID generator.
    pub fn new(default_options: BrantaApiOptions) -> Self {
        Self::with_deps(
            default_options.clone(),
            Box::new(BrantaClient::new(default_options)),
            Box::new(AesEncryptionService),
            Box::new(GuidSecretGenerator),
        )
    }

    /// Same as [`Self::new`], attaching the integration-metrics token live tests send.
    /// An empty token sends no header.
    pub fn new_with_token(default_options: BrantaApiOptions, token: Option<String>) -> Self {
        let mut client = BrantaClient::new(default_options.clone());
        if let Some(token) = token.filter(|value| !value.is_empty()) {
            client = client.with_integration_metrics_token(token);
        }
        Self::with_deps(
            default_options,
            Box::new(client),
            Box::new(AesEncryptionService),
            Box::new(GuidSecretGenerator),
        )
    }

    /// Inject a client, AES implementation, and secret generator.
    pub fn with_deps(
        default_options: BrantaApiOptions,
        client: Box<dyn BrantaClientTrait>,
        aes: Box<dyn AesEncryptionTrait>,
        secret_generator: Box<dyn SecretGeneratorTrait>,
    ) -> Self {
        Self {
            default_options,
            client,
            aes,
            secret_generator,
        }
    }

    /// Parses a scanned QR or pasted text and looks it up.
    pub async fn verify(
        &self,
        input: &str,
        options: Option<&BrantaApiOptions>,
    ) -> Result<VerifyResult, BrantaError> {
        let parser = QrParser::new(input);
        let lookup = self.scanned_lookup(&parser);
        match self.verify_parsed(&parser, options).await {
            Ok(result) => Ok(result),
            Err(LookupFail::Tampered) => Ok(status_only(
                VerifyStatus::Tampered,
                self.build_verify_url(options, &lookup, &IndexMap::new()),
            )),
            Err(LookupFail::Incomplete) => Ok(status_only(
                VerifyStatus::Incomplete,
                self.build_verify_url(options, &lookup, &IndexMap::new()),
            )),
            Err(LookupFail::Other(err)) => Err(err),
        }
    }

    fn scanned_lookup(&self, parser: &QrParser) -> String {
        if parser.on_chain_encryption_text.is_empty() {
            parser.destination().unwrap_or("").to_string()
        } else {
            parser.on_chain_encryption_text.clone()
        }
    }

    async fn verify_parsed(
        &self,
        parser: &QrParser,
        options: Option<&BrantaApiOptions>,
    ) -> Result<VerifyResult, LookupFail> {
        let expected_on_chain = uniform_on_chain_address(parser)?;
        let lookup = self.scanned_lookup(parser);

        if parser.has_unverifiable_instruction {
            return Ok(status_only(
                VerifyStatus::Unknown,
                self.build_verify_url(options, &lookup, &IndexMap::new()),
            ));
        }

        if parser.is_on_chain_zk() {
            let additional: Vec<String> = parser
                .destinations
                .iter()
                .filter(|destination| derived_key_type(&destination.value).is_some())
                .map(|destination| destination.value.clone())
                .collect();
            if expected_on_chain.is_none() && additional.is_empty() {
                return Ok(status_only(
                    VerifyStatus::Unknown,
                    self.build_verify_url(options, &lookup, &IndexMap::new()),
                ));
            }
            let (payments, verify_url) = self
                .lookup_by_branta_id(
                    &parser.on_chain_encryption_text,
                    &parser.on_chain_encryption_secret,
                    &additional,
                    expected_on_chain.as_deref(),
                    &parser.expected_secret_key_types,
                    options,
                )
                .await?;
            return Ok(to_verify_result(payments, verify_url));
        }

        let destination = parser.destination().unwrap_or("");
        if derived_key_type(destination).is_none() {
            return Ok(status_only(
                VerifyStatus::Unknown,
                self.build_verify_url(options, destination, &IndexMap::new()),
            ));
        }

        let (payments, verify_url) = self.lookup_by_derived_key(destination, options).await?;
        Ok(to_verify_result(payments, verify_url))
    }

    async fn lookup_by_branta_id(
        &self,
        lookup_value: &str,
        encryption_key: &str,
        additional_hash_values: &[String],
        expected_on_chain_address: Option<&str>,
        expected_on_chain_types: &[DestinationType],
        options: Option<&BrantaApiOptions>,
    ) -> Result<(Vec<Payment>, String), LookupFail> {
        let mut payments = self
            .client
            .get_payments(lookup_value, options)
            .await
            .map_err(lookup_error)?;

        let mut keys = IndexMap::new();
        let mut bound = Vec::new();
        for payment in &mut payments {
            let on_chain_bound = self
                .decrypt_destinations(
                    payment,
                    encryption_key,
                    &mut keys,
                    expected_on_chain_address,
                    expected_on_chain_types,
                )
                .await?;
            let mut hashes_bound = true;
            for value in additional_hash_values {
                if !self
                    .decrypt_derived_key_destinations(payment, value, &mut keys)
                    .await?
                {
                    hashes_bound = false;
                }
            }
            let has_payable =
                expected_on_chain_address.is_some() || !additional_hash_values.is_empty();
            if has_payable && on_chain_bound && hashes_bound {
                bound.push(payment.clone());
            }
        }
        Ok((bound, self.build_verify_url(options, lookup_value, &keys)))
    }

    async fn lookup_by_derived_key(
        &self,
        destination_value: &str,
        options: Option<&BrantaApiOptions>,
    ) -> Result<(Vec<Payment>, String), LookupFail> {
        let normalized = destination_value.to_lowercase();
        let lookup_value = self
            .aes
            .encrypt(&normalized, &to_normalized_hash(&normalized), true)
            .await
            .map_err(LookupFail::Other)?;

        let mut payments = self
            .client
            .get_payments(&lookup_value, options)
            .await
            .map_err(lookup_error)?;

        let mut keys = IndexMap::new();
        let mut bound = Vec::new();
        for payment in &mut payments {
            if self
                .decrypt_derived_key_destinations(payment, &normalized, &mut keys)
                .await?
            {
                bound.push(payment.clone());
            }
        }
        Ok((bound, self.build_verify_url(options, &lookup_value, &keys)))
    }

    /// Encrypts a copy of `payment` and posts that copy.
    pub async fn add_payment(
        &self,
        payment: &Payment,
        options: Option<&BrantaApiOptions>,
    ) -> Result<AddPaymentResult, BrantaError> {
        let mut submitted = payment.clone();
        fold_description_into_metadata(&mut submitted);

        let mut dek = String::new();
        if submitted
            .metadata
            .as_deref()
            .is_some_and(|value| !value.is_empty())
            && !submitted.destinations.is_empty()
        {
            dek = self.secret_generator.generate();
            submitted.metadata = Some(
                self.aes
                    .encrypt(submitted.metadata.as_deref().unwrap_or(""), &dek, false)
                    .await?,
            );
        }

        let secret = self.secret_generator.generate();
        let mut encrypted_to_key: IndexMap<String, String> = IndexMap::new();

        for destination in &mut submitted.destinations {
            if destination.id.is_none() {
                destination.id = Some(Uuid::new_v4().to_string());
            }
            if destination.r#type.is_none() {
                destination.r#type = super::parser::detect_plain_text_type(&destination.value);
            }

            if destination.r#type.is_some_and(is_secret_key_address_type) {
                let ciphertext = self
                    .aes
                    .encrypt(
                        &destination.value,
                        &secret,
                        self.secret_generator.deterministic_nonce(),
                    )
                    .await?;
                destination.value = ciphertext.clone();
                encrypted_to_key.insert(ciphertext, secret.clone());
                if !dek.is_empty() {
                    destination.encrypted_dek = Some(self.aes.encrypt(&dek, &secret, false).await?);
                }
                continue;
            }

            let Some(derived) = derived_key_type(&destination.value) else {
                return Err(BrantaError::UnsupportedDestinationType(
                    destination_type_name(destination.r#type),
                ));
            };
            if destination.r#type.is_none() {
                destination.r#type = Some(derived);
            }
            let normalized = destination.value.to_lowercase();
            let key = to_normalized_hash(&normalized);
            let ciphertext = self.aes.encrypt(&normalized, &key, true).await?;
            destination.value = ciphertext.clone();
            encrypted_to_key.insert(ciphertext, key.clone());
            if !dek.is_empty() {
                destination.encrypted_dek = Some(self.aes.encrypt(&dek, &key, false).await?);
            }
        }

        let primary_value = submitted
            .destinations
            .first()
            .map(|destination| destination.value.clone())
            .unwrap_or_default();

        let response = self
            .client
            .post_payment(submitted, options)
            .await?
            .ok_or(BrantaError::NoPaymentReturned)?;

        let mut keys = IndexMap::new();
        for destination in &response.destinations {
            let Some(id) = destination.id.clone() else {
                continue;
            };
            if let Some(key) = encrypted_to_key.get(&destination.value) {
                keys.entry(id).or_insert_with(|| key.clone());
            }
        }

        Ok(AddPaymentResult {
            verify_url: self.build_verify_url(options, &primary_value, &keys),
            payment: response,
            secret,
        })
    }

    pub async fn is_api_key_valid(
        &self,
        options: Option<&BrantaApiOptions>,
    ) -> Result<bool, BrantaError> {
        self.client.is_api_key_valid(options).await
    }

    async fn decrypt_destinations(
        &self,
        payment: &mut Payment,
        encryption_key: &str,
        keys: &mut IndexMap<String, String>,
        expected_on_chain_address: Option<&str>,
        expected_on_chain_types: &[DestinationType],
    ) -> Result<bool, LookupFail> {
        let mut on_chain_bound = expected_on_chain_address.is_none();
        let mut decrypted_expected_rail = false;
        for index in 0..payment.destinations.len() {
            if !payment.destinations[index].is_encrypted {
                continue;
            }
            let Some(dest_type) = payment.destinations[index].r#type else {
                continue;
            };
            if !is_secret_key_address_type(dest_type) {
                continue;
            }
            // Outside this QR's rail family (e.g. bitcoin when scanning pol:) — leave encrypted.
            if !expected_on_chain_types.is_empty() && !expected_on_chain_types.contains(&dest_type)
            {
                continue;
            }
            if encryption_key.is_empty() {
                continue;
            }
            let Ok(plaintext) = self
                .aes
                .decrypt(&payment.destinations[index].value, encryption_key)
                .await
            else {
                continue;
            };
            decrypted_expected_rail = true;
            // Match-if-any within the family: a sibling rail with a different address stays encrypted.
            if expected_on_chain_address
                .is_some_and(|expected| !addresses_match(&plaintext, expected))
            {
                continue;
            }
            if expected_on_chain_address.is_some() {
                on_chain_bound = true;
            }
            payment.destinations[index].value = plaintext;
            payment.destinations[index].is_encrypted = false;
            if let Some(id) = payment.destinations[index].id.clone() {
                keys.entry(id).or_insert_with(|| encryption_key.to_string());
            }
            self.try_decrypt_metadata(payment, index, encryption_key)
                .await;
        }
        // Tampered only when a family rail decrypted and none matched the scanned address.
        if expected_on_chain_address.is_some() && !on_chain_bound && decrypted_expected_rail {
            return Err(LookupFail::Tampered);
        }
        Ok(on_chain_bound)
    }

    /// Reports whether a destination of `plain_value`'s type decrypted to that value.
    /// A different plaintext is tampered for the whole call.
    async fn decrypt_derived_key_destinations(
        &self,
        payment: &mut Payment,
        plain_value: &str,
        keys: &mut IndexMap<String, String>,
    ) -> Result<bool, LookupFail> {
        let Some(derived) = derived_key_type(plain_value) else {
            return Ok(false);
        };
        let key = to_normalized_hash(plain_value);
        let mut bound = false;
        for index in 0..payment.destinations.len() {
            if !payment.destinations[index].is_encrypted
                || payment.destinations[index].r#type != Some(derived)
            {
                continue;
            }
            let Ok(plaintext) = self
                .aes
                .decrypt(&payment.destinations[index].value, &key)
                .await
            else {
                continue;
            };
            if !plaintext.eq_ignore_ascii_case(plain_value) {
                return Err(LookupFail::Tampered);
            }
            payment.destinations[index].value = plaintext;
            payment.destinations[index].is_encrypted = false;
            if let Some(id) = payment.destinations[index].id.clone() {
                keys.entry(id).or_insert_with(|| key.clone());
            }
            self.try_decrypt_metadata(payment, index, &key).await;
            bound = true;
        }
        Ok(bound)
    }

    async fn try_decrypt_metadata(&self, payment: &mut Payment, index: usize, key_used: &str) {
        if payment.is_metadata_decrypted {
            return;
        }
        let Some(encrypted_dek) = payment.destinations[index]
            .encrypted_dek
            .clone()
            .filter(|value| !value.is_empty())
        else {
            return;
        };
        let Some(metadata) = payment.metadata.clone().filter(|value| !value.is_empty()) else {
            return;
        };
        let Ok(dek) = self.aes.decrypt(&encrypted_dek, key_used).await else {
            return;
        };
        let Ok(plaintext) = self.aes.decrypt(&metadata, &dek).await else {
            return;
        };
        payment.metadata = Some(plaintext);
        payment.is_metadata_decrypted = true;
        lift_description_from_metadata(payment);
    }

    fn build_verify_url(
        &self,
        options: Option<&BrantaApiOptions>,
        payment_lookup: &str,
        keys: &IndexMap<String, String>,
    ) -> String {
        let base = self
            .default_options
            .get_base_url(options)
            .trim_end_matches('/');
        let encoded = utf8_percent_encode(payment_lookup, PATH_SEGMENT);
        let mut url = format!("{base}/v2/verify/{encoded}");
        url.push_str(&to_url_fragment(keys));
        url
    }
}

fn destination_type_name(r#type: Option<DestinationType>) -> String {
    match r#type {
        Some(DestinationType::BitcoinAddress) => "bitcoin_address",
        Some(DestinationType::Bolt11) => "bolt11",
        Some(DestinationType::ArkAddress) => "ark_address",
        Some(DestinationType::SilentPayment) => "silent_payment",
        Some(DestinationType::UsdtPolygon) => "usdt_polygon",
        Some(DestinationType::UsdcPolygon) => "usdc_polygon",
        Some(DestinationType::UsdtEthereum) => "usdt_ethereum",
        Some(DestinationType::UsdcEthereum) => "usdc_ethereum",
        Some(DestinationType::UsdtBsc) => "usdt_bsc",
        Some(DestinationType::UsdcBsc) => "usdc_bsc",
        Some(DestinationType::UsdtTron) => "usdt_tron",
        Some(DestinationType::UsdtTon) => "usdt_ton",
        Some(DestinationType::UsdtSolana) => "usdt_solana",
        Some(DestinationType::UsdcSolana) => "usdc_solana",
        Some(DestinationType::UsdtBase) => "usdt_base",
        Some(DestinationType::UsdcBase) => "usdc_base",
        Some(DestinationType::UsdtArbitrum) => "usdt_arbitrum",
        Some(DestinationType::UsdcArbitrum) => "usdc_arbitrum",
        None => "unknown",
    }
    .to_string()
}

fn fold_description_into_metadata(payment: &mut Payment) {
    let Some(description) = payment
        .description
        .clone()
        .filter(|value| !value.is_empty())
    else {
        return;
    };
    let mut metadata_map: serde_json::Map<String, serde_json::Value> = payment
        .metadata
        .as_deref()
        .filter(|value| !value.is_empty())
        .and_then(|value| serde_json::from_str(value).ok())
        .unwrap_or_default();
    metadata_map
        .entry("description")
        .or_insert_with(|| serde_json::Value::String(description));
    if let Ok(encoded) = serde_json::to_string(&metadata_map) {
        payment.metadata = Some(encoded);
        payment.description = None;
    }
}

fn lift_description_from_metadata(payment: &mut Payment) {
    let Some(metadata) = payment.metadata.as_deref() else {
        return;
    };
    let Ok(metadata_map) =
        serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(metadata)
    else {
        return;
    };
    if let Some(description) = metadata_map
        .get("description")
        .and_then(|value| value.as_str())
    {
        payment.description = Some(description.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enums::BrantaEnvironment;
    use crate::models::Destination;
    use async_trait::async_trait;
    use std::sync::Mutex;

    use super::super::encryption::encrypt;
    use crate::enums::{EvmTokenRail, EVM_TOKEN_RAILS};

    const ADDRESS: &str = "bc1qmerchant";
    const SECRET: &str = "branta-secret";
    const USDT_POLYGON: &str = "0x278297528c32eCa01295B0d2135984d3442ec963";
    const USDC_POLYGON: &str = "0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B";
    const DEPOSIT: &str = "0xAbCdEf0123456789aBcDeF0123456789AbCdEf01";
    const SIBLING_DEPOSIT: &str = "0x2222222222222222222222222222222222222222";
    const SWAPPED_DEPOSIT: &str = "0x1111111111111111111111111111111111111111";

    struct ScriptedClient {
        payments: Mutex<Result<Vec<Payment>, bool>>,
        posts: Mutex<Vec<Payment>>,
    }

    impl ScriptedClient {
        fn payments(payments: Vec<Payment>) -> Self {
            Self {
                payments: Mutex::new(Ok(payments)),
                posts: Mutex::new(Vec::new()),
            }
        }

        fn incomplete() -> Self {
            Self {
                payments: Mutex::new(Err(true)),
                posts: Mutex::new(Vec::new()),
            }
        }

        fn capture() -> Self {
            Self {
                payments: Mutex::new(Ok(Vec::new())),
                posts: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl BrantaClientTrait for ScriptedClient {
        async fn get_payments<'a>(
            &'a self,
            _destination_value: &'a str,
            _options: Option<&'a BrantaApiOptions>,
        ) -> Result<Vec<Payment>, BrantaError> {
            match &*self.payments.lock().unwrap() {
                Ok(payments) => Ok(payments.clone()),
                Err(_) => Err(BrantaError::Incomplete),
            }
        }

        async fn post_payment<'a>(
            &'a self,
            payment: Payment,
            _options: Option<&'a BrantaApiOptions>,
        ) -> Result<Option<Payment>, BrantaError> {
            self.posts.lock().unwrap().push(payment.clone());
            Ok(Some(payment))
        }

        async fn is_api_key_valid<'a>(
            &'a self,
            _options: Option<&'a BrantaApiOptions>,
        ) -> Result<bool, BrantaError> {
            Ok(true)
        }
    }

    struct FixedSecret;

    impl SecretGeneratorTrait for FixedSecret {
        fn generate(&self) -> String {
            "11111111-1111-4111-8111-111111111111".into()
        }

        fn deterministic_nonce(&self) -> bool {
            true
        }
    }

    struct PolygonSecret;

    impl SecretGeneratorTrait for PolygonSecret {
        fn generate(&self) -> String {
            "polygon-secret".into()
        }

        fn deterministic_nonce(&self) -> bool {
            true
        }
    }

    fn service(client: ScriptedClient) -> BrantaService {
        BrantaService::with_deps(
            BrantaApiOptions::new(BrantaEnvironment::Staging),
            Box::new(client),
            Box::new(AesEncryptionService),
            Box::new(FixedSecret),
        )
    }

    fn service_with_secret(
        client: ScriptedClient,
        secret: Box<dyn SecretGeneratorTrait>,
    ) -> BrantaService {
        BrantaService::with_deps(
            BrantaApiOptions::new(BrantaEnvironment::Staging),
            Box::new(client),
            Box::new(AesEncryptionService),
            secret,
        )
    }

    fn bolt11_payment(plaintext: &str, key_source: &str) -> Payment {
        let key = to_normalized_hash(&key_source.to_lowercase());
        Payment {
            destinations: vec![Destination {
                value: encrypt(&plaintext.to_lowercase(), &key, true).unwrap(),
                is_primary: true,
                is_encrypted: true,
                r#type: Some(DestinationType::Bolt11),
                id: Some("dest-1".into()),
                encrypted_dek: None,
            }],
            ..Payment::default()
        }
    }

    fn encrypted_bitcoin(address: &str, secret: &str, destination_id: &str) -> Destination {
        Destination {
            value: encrypt(address, secret, true).unwrap(),
            is_primary: true,
            is_encrypted: true,
            r#type: Some(DestinationType::BitcoinAddress),
            id: Some(destination_id.into()),
            encrypted_dek: None,
        }
    }

    fn encrypted_polygon(
        address: &str,
        destination_type: DestinationType,
        secret: &str,
        destination_id: &str,
    ) -> Destination {
        Destination {
            value: encrypt(address, secret, true).unwrap(),
            is_primary: false,
            is_encrypted: true,
            r#type: Some(destination_type),
            id: Some(destination_id.into()),
            encrypted_dek: None,
        }
    }

    fn bitcoin_qr(address: &str, encrypted: &str, secret: &str) -> String {
        format!("bitcoin:{address}?branta_id={encrypted}&branta_secret={secret}")
    }

    fn rail(destination_type: DestinationType) -> &'static EvmTokenRail {
        EVM_TOKEN_RAILS
            .iter()
            .find(|rail| rail.destination_type == destination_type)
            .unwrap()
    }

    /// ERC-681 transfer URI for `destination_type` with the branta params.
    fn transfer_uri(
        destination_type: DestinationType,
        address: &str,
        encrypted: &str,
        secret: &str,
    ) -> String {
        let rail = rail(destination_type);
        format!(
            "ethereum:{}@{}/transfer?address={address}&uint256=50000000&branta_id={encrypted}&branta_secret={secret}",
            rail.contract, rail.chain_id
        )
    }

    /// A payment with one encrypted destination per `(type, address)` pair.
    fn payment_of(items: &[(DestinationType, &str)]) -> (Payment, Vec<String>) {
        let mut ciphertexts = Vec::new();
        let destinations = items
            .iter()
            .enumerate()
            .map(|(i, (destination_type, address))| {
                let dest =
                    encrypted_polygon(address, *destination_type, SECRET, &format!("zk-{i}"));
                ciphertexts.push(dest.value.clone());
                dest
            })
            .collect();
        (
            Payment {
                destinations,
                ..Payment::default()
            },
            ciphertexts,
        )
    }

    async fn verify_transfer(payment: Payment, qr: &str) -> crate::models::VerifyResult {
        service(ScriptedClient::payments(vec![payment]))
            .verify(qr, None)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn plain_address_is_unknown_without_a_lookup() {
        let svc = service(ScriptedClient::incomplete());
        let result = svc.verify("bc1qmerchant", None).await.unwrap();
        assert_eq!(result.status, VerifyStatus::Unknown);
        assert!(result.payments.is_empty());
        assert!(result.matched_destinations.is_empty());
        assert!(result
            .verify_url
            .starts_with("https://staging.guardrail.branta.pro/v2/verify/bc1qmerchant"));
        assert!(!result.verify_url.contains('#'));
    }

    #[tokio::test]
    async fn bolt11_match_decrypts() {
        let invoice = "lnbc10testinvoice";
        let svc = service(ScriptedClient::payments(vec![bolt11_payment(
            invoice, invoice,
        )]));
        let result = svc.verify(invoice, None).await.unwrap();
        assert_eq!(result.status, VerifyStatus::Match);
        assert_eq!(result.payments[0].destinations[0].value, invoice);
        assert_eq!(result.matched_destinations.len(), 1);
        assert!(result.verify_url.contains("#k-dest-1="));
    }

    #[tokio::test]
    async fn derived_key_plaintext_mismatch_is_tampered() {
        let scanned = "lnbc10realinvoice";
        let svc = service(ScriptedClient::payments(vec![bolt11_payment(
            "lnbc10evilinvoice",
            scanned,
        )]));
        let result = svc.verify(scanned, None).await.unwrap();
        assert_eq!(result.status, VerifyStatus::Tampered);
        assert!(result.payments.is_empty());
        assert!(result.matched_destinations.is_empty());
        assert!(!result.verify_url.contains('#'));
    }

    #[tokio::test]
    async fn server_error_is_incomplete() {
        let svc = service(ScriptedClient::incomplete());
        let result = svc.verify("lnbc10realinvoice", None).await.unwrap();
        assert_eq!(result.status, VerifyStatus::Incomplete);
        assert!(!result.verify_url.contains('#'));
    }

    #[tokio::test]
    async fn branta_params_without_a_payable_destination_do_not_get() {
        let svc = service(ScriptedClient::incomplete());
        let result = svc
            .verify("bitcoin:?branta_id=abc&branta_secret=def", None)
            .await
            .unwrap();
        assert_eq!(result.status, VerifyStatus::Unknown);
    }

    #[tokio::test]
    async fn conflicting_on_chain_addresses_are_tampered() {
        let svc = service(ScriptedClient::incomplete());
        let result = svc
            .verify("bitcoin:bc1qaaa?bc=bc1qbbb", None)
            .await
            .unwrap();
        assert_eq!(result.status, VerifyStatus::Tampered);
    }

    #[tokio::test]
    async fn combined_branta_qr_decrypts_address_and_invoice() {
        const INVOICE: &str = "lnbc10u1p4w23tzpp5example";
        let btc = encrypted_bitcoin(ADDRESS, SECRET, "zk-btc");
        let bolt_key = to_normalized_hash(&INVOICE.to_lowercase());
        let bolt = Destination {
            value: encrypt(&INVOICE.to_lowercase(), &bolt_key, true).unwrap(),
            is_primary: false,
            is_encrypted: true,
            r#type: Some(DestinationType::Bolt11),
            id: Some("zk-bolt11".into()),
            encrypted_dek: None,
        };
        let ciphertext = btc.value.clone();
        let svc = service(ScriptedClient::payments(vec![Payment {
            destinations: vec![btc, bolt],
            ..Payment::default()
        }]));
        let qr = format!(
            "bitcoin:{ADDRESS}?lightning={INVOICE}&branta_id={ciphertext}&branta_secret={SECRET}"
        );
        let result = svc.verify(&qr, None).await.unwrap();
        assert_eq!(result.status, VerifyStatus::Match);
        assert_eq!(result.payments[0].destinations[0].value, ADDRESS);
        assert_eq!(
            result.payments[0].destinations[1].value.to_lowercase(),
            INVOICE.to_lowercase()
        );
        assert_eq!(result.matched_destinations.len(), 2);
        assert_eq!(
            result.matched_destinations[0].r#type,
            Some(DestinationType::BitcoinAddress)
        );
        assert_eq!(
            result.matched_destinations[1].r#type,
            Some(DestinationType::Bolt11)
        );
    }

    #[tokio::test]
    async fn combined_branta_qr_swapped_address_is_tampered() {
        const INVOICE: &str = "lnbc10u1p4w23tzpp5example";
        let btc = encrypted_bitcoin("bc1qother", SECRET, "zk-btc");
        let ciphertext = btc.value.clone();
        let svc = service(ScriptedClient::payments(vec![Payment {
            destinations: vec![btc],
            ..Payment::default()
        }]));
        let qr = format!(
            "bitcoin:{ADDRESS}?lightning={INVOICE}&branta_id={ciphertext}&branta_secret={SECRET}"
        );
        let result = svc.verify(&qr, None).await.unwrap();
        assert_eq!(result.status, VerifyStatus::Tampered);
        assert!(result.payments.is_empty());
    }

    #[tokio::test]
    async fn combined_branta_qr_attacker_lightning_is_unknown() {
        // Payment only has bitcoin — attacker bolt11 cannot bind (same as the other SDKs).
        let btc = encrypted_bitcoin(ADDRESS, SECRET, "zk-btc");
        let ciphertext = btc.value.clone();
        let svc = service(ScriptedClient::payments(vec![Payment {
            destinations: vec![btc],
            ..Payment::default()
        }]));
        let qr = format!(
            "bitcoin:{ADDRESS}?lightning=lnbc1attacker&branta_id={ciphertext}&branta_secret={SECRET}"
        );
        let result = svc.verify(&qr, None).await.unwrap();
        assert_eq!(result.status, VerifyStatus::Unknown);
    }

    #[tokio::test]
    async fn bitcoin_match_sets_matched_destinations() {
        let dest = encrypted_bitcoin(ADDRESS, SECRET, "dest-1");
        let ciphertext = dest.value.clone();
        let svc = service(ScriptedClient::payments(vec![Payment {
            destinations: vec![dest],
            ..Payment::default()
        }]));
        let result = svc
            .verify(&bitcoin_qr(ADDRESS, &ciphertext, SECRET), None)
            .await
            .unwrap();
        assert_eq!(result.status, VerifyStatus::Match);
        assert_eq!(result.matched_destinations.len(), 1);
        assert_eq!(
            result.matched_destinations[0].r#type,
            Some(DestinationType::BitcoinAddress)
        );
        assert_eq!(result.matched_destinations[0].value, ADDRESS);
    }

    #[tokio::test]
    async fn add_payment_keeps_caller_plaintext_and_omits_unset_ttl() {
        let client = CaptureClient;
        let svc = BrantaService::with_deps(
            BrantaApiOptions::new(BrantaEnvironment::Staging),
            Box::new(client),
            Box::new(AesEncryptionService),
            Box::new(FixedSecret),
        );
        let payment = crate::PaymentBuilder::new()
            .set_description("hello")
            .add_destination("bc1qexample", Some(DestinationType::BitcoinAddress))
            .build();
        let result = svc.add_payment(&payment, None).await.unwrap();
        assert_eq!(payment.destinations[0].value, "bc1qexample");
        assert_eq!(payment.description.as_deref(), Some("hello"));
        assert_ne!(result.payment.destinations[0].value, "bc1qexample");
        assert!(result.verify_url.contains("#k-resp-id="));
        assert_eq!(result.secret, "11111111-1111-4111-8111-111111111111");
    }

    #[tokio::test]
    async fn unencryptable_destination_is_rejected() {
        let svc = service(ScriptedClient::payments(Vec::new()));
        let payment = crate::PaymentBuilder::new()
            .add_destination("lno1offer", None)
            .build();
        let err = svc.add_payment(&payment, None).await.unwrap_err();
        assert!(matches!(err, BrantaError::UnsupportedDestinationType(_)));
        assert_eq!(payment.destinations[0].value, "lno1offer");
    }

    #[tokio::test]
    async fn every_rail_matches_and_sets_matched_destinations() {
        for rail in EVM_TOKEN_RAILS {
            let t = rail.destination_type;
            let (payment, cipher) = payment_of(&[(t, DEPOSIT)]);
            let result =
                verify_transfer(payment, &transfer_uri(t, DEPOSIT, &cipher[0], SECRET)).await;
            assert_eq!(result.status, VerifyStatus::Match, "{t:?}");
            assert_eq!(result.matched_destinations.len(), 1, "{t:?}");
            assert_eq!(result.matched_destinations[0].r#type, Some(t));
            assert_eq!(result.matched_destinations[0].value, DEPOSIT);
            assert!(result.verify_url.contains("#k-zk-0="), "{t:?}");
        }
    }

    #[tokio::test]
    async fn every_rail_matches_a_lowercase_deposit() {
        for rail in EVM_TOKEN_RAILS {
            let t = rail.destination_type;
            let (payment, cipher) = payment_of(&[(t, DEPOSIT)]);
            let qr = transfer_uri(t, &DEPOSIT.to_ascii_lowercase(), &cipher[0], SECRET);
            let result = verify_transfer(payment, &qr).await;
            assert_eq!(result.status, VerifyStatus::Match, "{t:?}");
            assert_eq!(result.matched_destinations[0].value, DEPOSIT);
        }
    }

    #[tokio::test]
    async fn upper_case_0x_deposit_prefix_matches() {
        let t = DestinationType::UsdtBase;
        let (payment, cipher) = payment_of(&[(t, DEPOSIT)]);
        let mixed = format!("0X{}", &DEPOSIT[2..]);
        let result = verify_transfer(payment, &transfer_uri(t, &mixed, &cipher[0], SECRET)).await;
        assert_eq!(result.status, VerifyStatus::Match);
    }

    #[tokio::test]
    async fn every_rail_swapped_deposit_is_tampered() {
        for rail in EVM_TOKEN_RAILS {
            let t = rail.destination_type;
            let (payment, cipher) = payment_of(&[(t, DEPOSIT)]);
            let result = verify_transfer(
                payment,
                &transfer_uri(t, SWAPPED_DEPOSIT, &cipher[0], SECRET),
            )
            .await;
            assert_eq!(result.status, VerifyStatus::Tampered, "{t:?}");
            assert!(result.payments.is_empty());
            assert!(result.matched_destinations.is_empty());
            assert!(!result.verify_url.contains('#'));
        }
    }

    #[tokio::test]
    async fn contract_on_the_wrong_chain_is_unknown_without_a_lookup() {
        for rail in EVM_TOKEN_RAILS {
            let wrong_chain = if rail.chain_id == 1 { 137 } else { 1 };
            let qr = format!(
                "ethereum:{}@{wrong_chain}/transfer?address={DEPOSIT}&branta_id=abc&branta_secret={SECRET}",
                rail.contract
            );
            let result = service(ScriptedClient::incomplete())
                .verify(&qr, None)
                .await
                .unwrap();
            assert_eq!(
                result.status,
                VerifyStatus::Unknown,
                "{:?}",
                rail.destination_type
            );
        }
    }

    #[tokio::test]
    async fn every_rail_without_branta_params_is_unknown_without_a_lookup() {
        for rail in EVM_TOKEN_RAILS {
            let qr = format!(
                "ethereum:{}@{}/transfer?address={DEPOSIT}&uint256=1",
                rail.contract, rail.chain_id
            );
            let result = service(ScriptedClient::incomplete())
                .verify(&qr, None)
                .await
                .unwrap();
            assert_eq!(
                result.status,
                VerifyStatus::Unknown,
                "{:?}",
                rail.destination_type
            );
            assert!(!result.verify_url.contains('#'));
        }
    }

    #[tokio::test]
    async fn dual_token_payment_binds_only_the_scanned_token() {
        let usdt = DestinationType::UsdtBase;
        let usdc = DestinationType::UsdcBase;
        let (payment, cipher) = payment_of(&[(usdt, DEPOSIT), (usdc, DEPOSIT)]);
        let usdc_cipher = payment.destinations[1].value.clone();
        let result =
            verify_transfer(payment, &transfer_uri(usdt, DEPOSIT, &cipher[0], SECRET)).await;
        assert_eq!(result.status, VerifyStatus::Match);
        assert_eq!(result.matched_destinations.len(), 1);
        assert_eq!(result.matched_destinations[0].r#type, Some(usdt));
        let dests = &result.payments[0].destinations;
        assert!(!dests[0].is_encrypted);
        assert!(dests[1].is_encrypted);
        assert_eq!(dests[1].value, usdc_cipher);
    }

    #[tokio::test]
    async fn usdc_scan_against_a_usdt_only_payment_is_unknown() {
        let (payment, cipher) = payment_of(&[(DestinationType::UsdtBase, DEPOSIT)]);
        let qr = transfer_uri(DestinationType::UsdcBase, DEPOSIT, &cipher[0], SECRET);
        let result = verify_transfer(payment, &qr).await;
        assert_eq!(result.status, VerifyStatus::Unknown);
        assert!(result.matched_destinations.is_empty());
    }

    #[tokio::test]
    async fn ethereum_scan_against_a_polygon_only_payment_is_unknown() {
        let (payment, cipher) = payment_of(&[(DestinationType::UsdtPolygon, DEPOSIT)]);
        let qr = transfer_uri(DestinationType::UsdtEthereum, DEPOSIT, &cipher[0], SECRET);
        let result = verify_transfer(payment, &qr).await;
        assert_eq!(result.status, VerifyStatus::Unknown);
    }

    #[tokio::test]
    async fn same_type_sibling_with_another_address_stays_encrypted() {
        let t = DestinationType::UsdtArbitrum;
        let (payment, cipher) = payment_of(&[(t, SIBLING_DEPOSIT), (t, DEPOSIT)]);
        let sibling_cipher = cipher[0].clone();
        let result = verify_transfer(payment, &transfer_uri(t, DEPOSIT, &cipher[1], SECRET)).await;
        assert_eq!(result.status, VerifyStatus::Match);
        let dests = &result.payments[0].destinations;
        assert!(dests[0].is_encrypted);
        assert_eq!(dests[0].value, sibling_cipher);
        assert!(!dests[1].is_encrypted);
        assert_eq!(result.matched_destinations.len(), 1);
    }

    #[tokio::test]
    async fn erc681_scan_leaves_a_bitcoin_sibling_encrypted() {
        let t = DestinationType::UsdtPolygon;
        let (mut payment, cipher) = payment_of(&[(t, DEPOSIT)]);
        payment
            .destinations
            .insert(0, encrypted_bitcoin(ADDRESS, SECRET, "zk-btc"));
        let result = verify_transfer(payment, &transfer_uri(t, DEPOSIT, &cipher[0], SECRET)).await;
        assert_eq!(result.status, VerifyStatus::Match);
        let dests = &result.payments[0].destinations;
        assert_eq!(dests[0].r#type, Some(DestinationType::BitcoinAddress));
        assert!(dests[0].is_encrypted);
        assert!(!dests[1].is_encrypted);
        assert_eq!(dests[1].value, DEPOSIT);
    }

    #[tokio::test]
    async fn bitcoin_scan_leaves_an_evm_sibling_encrypted() {
        let dest = encrypted_bitcoin(ADDRESS, SECRET, "zk-btc");
        let ciphertext = dest.value.clone();
        let (evm, _) = payment_of(&[(DestinationType::UsdtPolygon, DEPOSIT)]);
        let svc = service(ScriptedClient::payments(vec![Payment {
            destinations: vec![dest, evm.destinations[0].clone()],
            ..Payment::default()
        }]));
        let result = svc
            .verify(&bitcoin_qr(ADDRESS, &ciphertext, SECRET), None)
            .await
            .unwrap();
        assert_eq!(result.status, VerifyStatus::Match);
        let dests = &result.payments[0].destinations;
        assert!(!dests[0].is_encrypted);
        assert!(dests[1].is_encrypted);
        assert_eq!(dests[1].r#type, Some(DestinationType::UsdtPolygon));
    }

    #[tokio::test]
    async fn wrong_secret_is_unknown() {
        let t = DestinationType::UsdcArbitrum;
        let (payment, cipher) = payment_of(&[(t, DEPOSIT)]);
        let result = verify_transfer(
            payment,
            &transfer_uri(t, DEPOSIT, &cipher[0], "wrong-secret"),
        )
        .await;
        assert_eq!(result.status, VerifyStatus::Unknown);
    }

    #[tokio::test]
    async fn description_is_lifted_from_decrypted_metadata() {
        let dek = "dek-evm";
        let metadata = r#"{"description":"USDT invoice"}"#;
        let t = DestinationType::UsdtBase;
        let (mut payment, cipher) = payment_of(&[(t, DEPOSIT)]);
        payment.metadata = Some(encrypt(metadata, dek, true).unwrap());
        payment.destinations[0].encrypted_dek = Some(encrypt(dek, SECRET, true).unwrap());
        let result = verify_transfer(payment, &transfer_uri(t, DEPOSIT, &cipher[0], SECRET)).await;
        assert_eq!(result.status, VerifyStatus::Match);
        assert_eq!(
            result.payments[0].description.as_deref(),
            Some("USDT invoice")
        );
    }

    #[tokio::test]
    async fn bare_address_is_unknown() {
        let result = service(ScriptedClient::incomplete())
            .verify(USDT_POLYGON, None)
            .await
            .unwrap();
        assert_eq!(result.status, VerifyStatus::Unknown);
    }

    #[tokio::test]
    async fn other_functions_authority_forms_and_unparseable_input_are_unknown_without_a_lookup() {
        let t = DestinationType::UsdcBase;
        let c = rail(t).contract;
        let tail = format!("address={DEPOSIT}&branta_id=abc&branta_secret={SECRET}");
        let inputs = [
            format!("ethereum:{c}@8453/approve?{tail}"),
            format!("ethereum:{c}@8453/transferFrom?{tail}"),
            format!("ethereum://{c}@8453/transfer?{tail}"),
            format!("ethereum:{c}/transfer?{tail}"),
            format!("ethereum:{c}@0x2105/transfer?{tail}"),
            "ethereum://[bad/transfer".to_string(),
            "bitcoin://[bad".to_string(),
            format!("ethereum:{c}@{}/transfer?{tail}", "9".repeat(5000)),
            format!("ethereum:{c}@8453/transfer#x?{tail}"),
        ];
        for qr in inputs {
            let result = service(ScriptedClient::incomplete())
                .verify(&qr, None)
                .await
                .unwrap();
            assert_eq!(
                result.status,
                VerifyStatus::Unknown,
                "{}",
                qr.chars().take(40).collect::<String>()
            );
        }
    }

    #[tokio::test]
    async fn removed_chain_schemes_are_unknown_without_a_lookup() {
        for (scheme, address) in [
            ("pol", USDT_POLYGON),
            ("eth", USDT_ETHEREUM),
            ("bsc", USDT_ETHEREUM),
            ("tron", USDT_TRON),
            ("ton", "UQBexample"),
            ("sol", USDC_SOLANA),
        ] {
            let qr = format!("{scheme}:{address}?value=50&branta_id=abc&branta_secret={SECRET}");
            let result = service(ScriptedClient::incomplete())
                .verify(&qr, None)
                .await
                .unwrap();
            assert_eq!(result.status, VerifyStatus::Unknown, "{scheme}");
            assert!(!result.verify_url.contains('#'));
        }
    }

    #[tokio::test]
    async fn add_payment_encrypts_usdt_and_usdc_polygon() {
        let client = ScriptedClient::capture();
        let svc = service_with_secret(client, Box::new(PolygonSecret));
        let caller = crate::PaymentBuilder::new()
            .add_destination(USDT_POLYGON, Some(DestinationType::UsdtPolygon))
            .build();
        let result = svc.add_payment(&caller, None).await.unwrap();
        assert_eq!(caller.destinations[0].value, USDT_POLYGON);
        assert_ne!(result.payment.destinations[0].value, USDT_POLYGON);
        assert_eq!(
            result.payment.destinations[0].r#type,
            Some(DestinationType::UsdtPolygon)
        );
        assert_eq!(result.secret, "polygon-secret");

        let usdc_client = ScriptedClient::capture();
        let usdc_svc = service_with_secret(usdc_client, Box::new(PolygonSecret));
        let usdc = crate::PaymentBuilder::new()
            .add_destination(USDC_POLYGON, Some(DestinationType::UsdcPolygon))
            .build();
        let usdc_result = usdc_svc.add_payment(&usdc, None).await.unwrap();
        assert_eq!(
            usdc_result.payment.destinations[0].r#type,
            Some(DestinationType::UsdcPolygon)
        );
        assert_ne!(usdc_result.payment.destinations[0].value, USDC_POLYGON);
    }

    #[tokio::test]
    async fn add_payment_encrypts_every_evm_rail() {
        for rail in EVM_TOKEN_RAILS {
            let t = rail.destination_type;
            let svc = service_with_secret(ScriptedClient::capture(), Box::new(PolygonSecret));
            let caller = crate::PaymentBuilder::new()
                .add_destination(DEPOSIT, Some(t))
                .build();
            let result = svc.add_payment(&caller, None).await.unwrap();
            assert_eq!(caller.destinations[0].value, DEPOSIT, "{t:?}");
            let posted = &result.payment.destinations[0];
            assert_eq!(posted.r#type, Some(t));
            assert_ne!(posted.value, DEPOSIT);
            assert_eq!(
                crate::v2::encryption::decrypt(&posted.value, "polygon-secret").unwrap(),
                DEPOSIT,
                "{t:?}"
            );
        }
    }

    #[tokio::test]
    async fn add_payment_bare_ox_without_type_is_unsupported() {
        let svc = service(ScriptedClient::capture());
        let payment = crate::PaymentBuilder::new()
            .add_destination(USDT_POLYGON, None)
            .build();
        let err = svc.add_payment(&payment, None).await.unwrap_err();
        assert!(matches!(err, BrantaError::UnsupportedDestinationType(_)));
    }

    const USDT_ETHEREUM: &str = "0xBF5550253939187432Ef4dccE8089765d3DCb47f";
    const USDT_TRON: &str = "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb";
    const USDC_SOLANA: &str = "7EqQdEULxWcraVx3mXKFjc84LhCkMGZCkRuDofycyinf";

    #[tokio::test]
    async fn bare_stablecoin_addresses_are_unknown_without_a_lookup() {
        for address in [USDT_ETHEREUM, USDT_TRON, USDC_SOLANA] {
            let svc = service(ScriptedClient::incomplete());
            let result = svc.verify(address, None).await.unwrap();
            assert_eq!(result.status, VerifyStatus::Unknown, "{address}");
        }
    }

    #[tokio::test]
    async fn add_payment_encrypts_usdt_tron_with_secret() {
        let svc = service_with_secret(ScriptedClient::capture(), Box::new(PolygonSecret));
        let caller = crate::PaymentBuilder::new()
            .add_destination(USDT_TRON, Some(DestinationType::UsdtTron))
            .build();
        let result = svc.add_payment(&caller, None).await.unwrap();
        assert_eq!(caller.destinations[0].value, USDT_TRON);
        let posted = &result.payment.destinations[0];
        assert_eq!(posted.r#type, Some(DestinationType::UsdtTron));
        assert_ne!(posted.value, USDT_TRON);
        assert_eq!(
            crate::v2::encryption::decrypt(&posted.value, "polygon-secret").unwrap(),
            USDT_TRON
        );
        assert_eq!(result.secret, "polygon-secret");
    }

    struct CaptureClient;

    #[async_trait]
    impl BrantaClientTrait for CaptureClient {
        async fn get_payments<'a>(
            &'a self,
            _destination_value: &'a str,
            _options: Option<&'a BrantaApiOptions>,
        ) -> Result<Vec<Payment>, BrantaError> {
            Ok(Vec::new())
        }

        async fn post_payment<'a>(
            &'a self,
            payment: Payment,
            _options: Option<&'a BrantaApiOptions>,
        ) -> Result<Option<Payment>, BrantaError> {
            let json = serde_json::to_value(&payment).unwrap();
            assert!(json.get("ttl").is_none());
            assert!(json.get("description").is_none());
            let metadata = json["metadata"].as_str().unwrap();
            assert!(!metadata.contains("hello"));
            let mut response = payment;
            response.destinations[0].id = Some("resp-id".into());
            Ok(Some(response))
        }

        async fn is_api_key_valid<'a>(
            &'a self,
            _options: Option<&'a BrantaApiOptions>,
        ) -> Result<bool, BrantaError> {
            Ok(true)
        }
    }
}
