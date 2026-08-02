# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.2.0] - 2026-07-25

### Added
- Initial release of the Branta Rust SDK.
- Feature-parity port of `branta-dotnet` 3.2.0 (and `branta-js`, `branta-dart`, `branta-python`, `branta-kotlin`).
- `BrantaService` with `get_payments`, `get_payments_by_qr_code`, `add_payment`, and `is_api_key_valid`.
- `PaymentBuilder` fluent builder with ZK support, metadata encryption, and child platform tagging.
- `QrParser` handles `bitcoin:`/`lightning:` URIs and plain-text values, with full query-string decoding.
- AES-256-GCM encryption with deterministic and random nonce modes.
- Zero-knowledge (ZK) destination support for Bitcoin addresses, BOLT-11, Ark, and silent payments.
- Metadata DEK-envelope encryption.
- `PrivacyMode::Strict` (default) and `PrivacyMode::Loose` enforcement.
- HMAC-SHA256 request signing support for parent platform flows.
- Full unit test coverage via mocked client/AES/secret-generator dependencies (`mockall`, `wiremock`).
- Integration tests against staging and production, reusing the same example QR-code fixtures as `branta-python`.
