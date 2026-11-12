# Branta Rust SDK

If you are implementing this SDK in a consumer project: product rules (send vs receive, `match` / `unknown` / `tampered`, parent platforms) live in the [developer docs](https://developer.branta.pro). `README.md` is the Rust crate — install, constructor, samples, and crypto.

---

## Developer notes (SDK contributors)

### Crate layout
- `src/lib.rs` — public exports: `BrantaService`, `PaymentBuilder`, `BrantaApiOptions`, `BrantaEnvironment`, `DestinationType`, `VerifyStatus`, `VerifyResult`, `AddPaymentResult`, `Payment`, `Destination`, `Platform`, `BrantaError`.
- `src/v2/` is private. `service.rs` orchestrates encrypt/decrypt. `client.rs` is the raw HTTP layer. Do not export `BrantaClient`, `QrParser`, AES types, `GuidSecretGenerator`, or rail-family helpers (`SECRET_KEY_URI_FAMILIES`, `is_secret_key_address_type`).
- `examples/branta_example.rs` — runnable demo.
- `tests/integration_test.rs` — live staging and production lookups, skipped unless `BRANTA_RUN_INTEGRATION=1`. Write tests (polygon / multi-rail round-trips / combos) also need `BRANTA_API_KEY`.
- `tests/public_api_test.rs` — locks the consumer surface.

### Build / test / release
- Build: `cargo build`
- Test: `cargo test`
- Live integration tests: `BRANTA_RUN_INTEGRATION=1 cargo test --test integration_test`
- Live multi-rail write: `BRANTA_RUN_INTEGRATION=1 BRANTA_API_KEY=… cargo test --test integration_test staging_secret_key_round_trip`
- Lint: `cargo clippy --all-targets -- -D warnings`
- Format: `cargo fmt --check`
- Release: bump `version` in `Cargo.toml`, add a `CHANGELOG.md` entry, `cargo publish`. Do not publish until asked.

### Key behaviors to preserve
- **Unencrypted destinations are not supported.** `verify` is the only lookup. A raw on-chain address (including testnet `tb1` / `bcrt1` / bare `0x`) is `unknown` and does not GET. `add_payment` encrypts every destination; types that cannot be encrypted return `UnsupportedDestinationType`.
- **`DestinationType` is only what `add_payment` accepts:** bitcoin, bolt11, ark, silent payment, and the stablecoin rails (`usdt_polygon` … `usdc_solana`). No `usdc_ton` yet. Pass stablecoin types explicitly. BIP21 extras this SDK cannot encrypt (`lno`, `pay`, non-bolt11 `lightning`) make `verify` return `unknown`.
- **Stablecoin verify** uses chain URIs (`pol:`, `eth:`, `bsc:`, `tron:`, `ton:`, `sol:`) match-if-any within the scheme's family; token is on `matched_destinations[].r#type`.
- **`verify` returns `VerifyResult`.** `match` includes `payments`, `matched_destinations`, and `verify_url`. `unknown`, `tampered`, and `incomplete` include only `verify_url`. Do not return an error for a swapped address. A 404 is `unknown`. 5xx, 429, no network, a timeout, or a malformed GET body are `incomplete`. `LogoUrlDomainMismatch` still returns an error. `branta_id` / `branta_secret` with no payable destination is `unknown` and does not GET. A bolt11 / Ark / silent-payment GET hit is `unknown` unless a destination of that type decrypts to the scanned value. A different plaintext is `tampered` for the whole call.
- **`verify_url` is always returned.** Format: `{apiOrigin}/v2/verify/{lookup}` plus a URL fragment built from per-destination encryption keys on `match`.
- **Encryption.** Bitcoin and stablecoin addresses use one UUID secret per `add_payment` call. bolt11, Ark, and silent payments use `SHA-256` of the lowercased value as uppercase hex. `add_payment` encrypts a copy. Description is folded into encrypted metadata and lifted back after decrypt. An unset TTL (`0`) is omitted. Wire `zk` is always `true`. Wire `zk_id` is `Destination.id`.
- **`BrantaApiOptions` is the constructor argument and the per-call override.** A missing environment uses staging. `hmac_secret` is deprecated — shared `api_key` + `set_child_platform` is the parent-platform path. Do not reintroduce `PrivacyMode`, `BrantaClientOptions`, `BrantaServerBaseUrl`, or `set_zk`.
- **`verify` parses first.** Multi-value payloads go through `QrParser` whether they came from a scan or a paste.
- **Crypto wire format must byte-for-byte match every sibling SDK.** See `src/v2/encryption.rs`. The checked-in vector is `Encrypt("hello world", "my-secret", true) == mPIKHc3ywVlsBHf3Lv2Rwpz2+fKE0kgUePq2m4fPIUidMuGEHVIB`.
- **Default HTTP timeout is 30s.** No retry logic.

### Logo-URL domain validation
`BrantaClient::verify_logo_urls` checks every payment in a GET response and every logo-bearing field. A mismatch returns `BrantaError::LogoUrlDomainMismatch(field)`. `verify` does not map that error to a status.

### Conventions
- Public API is the crate root. `src/v2` and rail-family helpers stay private.
- `BrantaService::new` for production. `BrantaService::new_with_token` attaches `BRANTA_INTEGRATION_METRICS_TOKEN` for live tests. `with_deps` injects the HTTP client, AES, and secret generator.
- `QrParser::new` is infallible. Unrecognized input is an untyped destination.
- Keep parity with `@branta-ops/branta` / Swift / Kotlin / Branta.NET / branta-go 4.3.0.
