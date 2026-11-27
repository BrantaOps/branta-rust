# Branta Rust SDK

Rust SDK published on crates.io as `branta`. Consumers (wallets, platforms, parent platforms) call `BrantaService` to look up or post payments to Branta. `README.md` is the install, constructor, samples, and crypto guide.

## Behavior contract

What `verify` returns and how ERC-681 is parsed: [Status rules](https://developer.branta.pro/setup/send/status-rules). Which rails encrypt with what key: [Encryption](https://developer.branta.pro/setup/receive/encryption). Send handling is on [Send](https://developer.branta.pro/setup/send), and the type list on [Destination types](https://developer.branta.pro/destination-types). Do not restate them here. Change the docs first, then the SDK.

Invariants that break silently. Check them before you change `verify` or `addPayment`:

- A raw on-chain address (including `tb1` / `bcrt1` / bare `0x`) is `unknown` and does not GET.
- A swapped address is `tampered`. `unknown`, `tampered`, and `incomplete` are returned, never thrown.
- The token is `matchedDestinations[].type`, never the URI scheme.
- A logo-domain mismatch throws. Every other lookup failure is a status.
- `addPayment` encrypts a copy and leaves the caller's `Payment` unchanged.
- The payment POST sends `X-Branta-SDK: <language>/<version>`. A GET never does. [SDK header](https://developer.branta.pro/tech/api/receive#sdk-header)
- Keep parity with every 4.x Branta SDK. A public method added or changed here is mirrored in each of them.

## Rust specifics

- The contract's names are snake_case here: `add_payment`, `matched_destinations[].r#type`, `verify_url`. "Throws" means the call returns a `BrantaError`. `BrantaError::LogoUrlDomainMismatch(field)` is returned, and `verify` does not map it to a status.
- `add_payment` returns `UnsupportedDestinationType` for a type it cannot encrypt.
- `Destination.id` is sent as `zk_id`. Wire `zk` is always `true`. An unset TTL (`0`) is omitted.
- `verify` parses first. Multi-value payloads go through `QrParser` whether they came from a scan or a paste.
- `DestinationType` is only what `add_payment` accepts. It also includes `usdt_tron`, `usdt_ton`, `usdt_solana`, and `usdc_solana`. They can be posted but no URI verifies them, and they are not on the public Destination types page. There is no `usdc_ton`.
- `BrantaApiOptions` is the constructor argument and the per-call override. A missing environment uses staging. `hmac_secret` signs `POST /v2/payments` for platforms with Require HMAC on and is not deprecated. For parent platforms, a shared `api_key` plus `set_brand` replaces the deprecated per-client HMAC flow.
- `set_brand` is the method and the wire field is `brand` (`{name, logo_url, logo_light_url}`). `set_child_platform` and `Payment.child_platform` stay only as deprecated aliases: the method delegates to `set_brand`, and `child_platform` is never sent. The effective brand is `brand`, else `child_platform`. A parsed payload accepts either key (`brand` wins) and mirrors it into both fields. Internal code must not call the deprecated names.
- Crypto output must match every sibling SDK byte for byte. The test vector is on the Encryption page. See `src/v2/encryption.rs`.
- Default HTTP timeout is 30s. No retry logic.
- Do not reintroduce `PrivacyMode`, `BrantaClientOptions`, `BrantaServerBaseUrl`, or `set_zk`.

## Crate layout

- `src/lib.rs` — public exports: `BrantaService`, `PaymentBuilder`, `BrantaApiOptions`, `BrantaEnvironment`, `DestinationType`, `VerifyStatus`, `VerifyResult`, `AddPaymentResult`, `Payment`, `Destination`, `Platform`, `BrantaError`.
- `src/v2/` is private. `service.rs` orchestrates encrypt/decrypt. `client.rs` is the raw HTTP layer. Do not export `BrantaClient`, `QrParser`, AES types, `GuidSecretGenerator`, or the rail table and helpers (`EVM_TOKEN_RAILS`, `evm_token_type`, `is_secret_key_address_type`).
- `examples/branta_example.rs` — runnable demo.
- `tests/integration_test.rs` — live staging and production lookups, skipped unless `BRANTA_RUN_INTEGRATION=1`. Write tests (multi-rail round-trips / combos) also need `BRANTA_API_KEY`.
- `tests/public_api_test.rs` — locks the consumer surface.

## Build / test / release

- Build: `cargo build`
- Test: `cargo test`
- Live integration tests: `BRANTA_RUN_INTEGRATION=1 cargo test --test integration_test`
- Live multi-rail write: `BRANTA_RUN_INTEGRATION=1 BRANTA_API_KEY=… cargo test --test integration_test staging_secret_key_round_trip`
- Lint: `cargo clippy --all-targets -- -D warnings`
- Format: `cargo fmt --check`
- Release: bump `version` in `Cargo.toml`, add a `CHANGELOG.md` entry, `cargo publish`, then tag the release commit `vX.Y.Z` and push the tag. Do not publish until asked.

## Conventions

- `BrantaService::new` for production. `BrantaService::new_with_token` attaches `BRANTA_INTEGRATION_METRICS_TOKEN` for live tests. `with_deps` injects the HTTP client, AES, and secret generator.
- `QrParser::new` is infallible. Unrecognized input is an untyped destination.
