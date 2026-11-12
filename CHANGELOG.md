# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.3.0] - 2026-11-12

### Added
- Multi-rail stablecoin destination types `UsdtEthereum`, `UsdcEthereum`, `UsdtBsc`, `UsdcBsc`, `UsdtTron`, `UsdtTon`, `UsdtSolana`, `UsdcSolana`. `add_payment` encrypts them with a random secret. `verify` parses `eth:`, `bsc:`, `tron:`, `ton:`, and `sol:` URIs with `branta_id` / `branta_secret`, match-if-any within the scheme's family. A bare address is `unknown`. Token is on `matched_destinations[].r#type`, not the URI scheme.
- Gated `staging_secret_key_round_trip` live coverage for every secret-key rail.
- `tests/public_api_test.rs` locks the consumer surface.

### Changed
- **Breaking for 4.2.0 callers:** rail-family lists / `SECRET_KEY_URI_FAMILIES` / `is_secret_key_address_type` / `is_polygon_evm_destination_type` are crate-private (match JS/Python/Dart/Swift/Kotlin/dotnet/Go consumer surface).
- Malformed GET JSON / bad payment rows map to `incomplete` (not a thrown decode error). Non-array 200 bodies decode as an empty list.
- Default HTTP client uses a 30s timeout so hung networks become `incomplete` on verify.
- `hmac_secret` on `BrantaApiOptions` is deprecated; prefer a shared `api_key` with `PaymentBuilder::set_child_platform`.
- CI gates line coverage at ≥80%.

### Notes
- `usdc_ton` is deferred until a platform names a concrete TON USDC jetton. Matches `@branta-ops/branta` / Python / Dart / Swift / Kotlin / Branta.NET / branta-go 4.3.0.

## [4.2.0] - 2026-11-10

### Added
- `DestinationType::UsdtPolygon` for Polygon USDT. `add_payment` encrypts the recipient with a random secret (same pattern as bitcoin). `verify` parses `pol:` URIs with `branta_id` / `branta_secret`; other query params (`value`, `currency`, `user`) are ignored for binding. A bare `0x` address is `unknown`. EVM address compare is case-insensitive.
- `DestinationType::UsdcPolygon` for Polygon USDC. Same secret-key encrypt / `pol:` verify path as `usdt_polygon`. Token is the destination type on the payment; `pol:` remains the Polygon EVM scheme for both.
- `POLYGON_EVM_DESTINATION_TYPES`, `is_polygon_evm_destination_type`, and `is_secret_key_address_type`.
- `VerifyResult.matched_destinations` on `match` — decrypted rails that bound the scan (token for `pol:` is on `type`).

### Changed
- `verify` of a `pol:` URI binds any Polygon EVM family member whose decrypted address matches (match-if-any).
- `pol:` parsing does not stamp a token `DestinationType` on the QR address. The scheme maps to the Polygon EVM family for verify; the token still comes from the matched payment destination.
- `verify` swap-checks only the secret-key rail family that matches the QR scheme, so a payment with both bitcoin and `usdt_polygon` no longer returns `tampered` for a valid single-rail QR.
- This release matches `@branta-ops/branta` / Branta.NET / branta-go / branta-swift / branta-kotlin / branta-python 4.2.0.

## [4.0.0] - 2026-11-02

### Changed
- **Breaking:** `verify` replaces `get_payments` and `get_payments_by_qr_code`. It returns `match`, `unknown`, `tampered`, or `incomplete`. A match includes payments and a verify URL. The other statuses include only the verify URL. A swapped address is `tampered`. A 404 is `unknown`. A 5xx, a 429, or no network is `incomplete`.
- **Breaking:** `DestinationType` is `bitcoin_address`, `bolt11`, `ark_address`, and `silent_payment`. `bolt12`, LNURL, lightning addresses, and tether are not destination types. A BIP21 extra this SDK cannot encrypt makes `verify` return `unknown`.
- **Breaking:** `PrivacyMode`, `BrantaClientOptions`, `BrantaServerBaseUrl`, `PaymentsResult`, and `PaymentBuilder::set_zk` are removed. Configure `BrantaApiOptions` with `environment`, `api_key`, and `hmac_secret`. A missing environment uses staging.
- **Breaking:** `add_payment` encrypts a copy of every destination and leaves the caller's `Payment` plaintext. Bitcoin addresses use a caller-supplied UUID secret. bolt11, Ark, and silent payments use a key derived from the normalized value. Description is stored inside encrypted metadata. An unset TTL is omitted so Guardrail applies the 7-day default.
- The public crate root exports `BrantaService`, `PaymentBuilder`, `BrantaApiOptions`, `BrantaEnvironment`, `DestinationType`, `VerifyStatus`, `VerifyResult`, and `AddPaymentResult`.

## [3.2.4] - 2026-10-29

### Security
- `get_payments_by_qr_code` now requires every payment instruction in a QR code to match a decrypted destination before returning a payment. A swapped address with a rewritten `branta_secret`, an added `lightning`/`ark`/`sp` leg, or a conflicting `bc=`/`tb=` no longer comes back as verified. Conflicting on-chain addresses (path, `bc=`, `tb=`) return `Err(BrantaError::Tampered)`. `bolt12`, `lno=`, `pay=`, and LNURL instructions cannot be bound and return no payments without a lookup. `QrParser` gains `has_unverifiable_instruction` and now parses `bc`, `tb`, `sp`, and `lno` params (ported from `branta-js` #78).

## [3.2.3] - 2026-10-28

### Added
- Recognize signet and regtest Ark addresses (`tark1`) as `ark_address`, alongside mainnet `ark1`. Strict-mode hash-ZK lookup and registration treat them the same way as `ark1`.
