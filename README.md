# Branta Rust SDK

Rust SDK for the [Branta](https://branta.pro) V2 API. Wallets call `verify` before sending. Platforms call `add_payment` so a wallet can verify the destination.

Status handling and parent platforms are in the [developer docs](https://developer.branta.pro).

# Requirements

- Rust 1.75 or higher
- [Tokio](https://tokio.rs)

# Installation

```bash
cargo add branta
```

# Quick start

```rust
use branta::{
    BrantaApiOptions, BrantaEnvironment, BrantaService, DestinationType, PaymentBuilder,
};

let mut options = BrantaApiOptions::new(BrantaEnvironment::Production);
options.api_key = Some(std::env::var("BRANTA_API_KEY").unwrap());
let service = BrantaService::new(options);

// Send: one call for a scan or a paste.
let result = service.verify(scanned_or_pasted, None).await?;
match result.status {
    branta::VerifyStatus::Match => {
        // Show the platform card and link result.verify_url.
        // Read result.payments[0].platform and .description.
    }
    branta::VerifyStatus::Tampered => {
        // Warn. Do not show a verified card.
    }
    branta::VerifyStatus::Unknown | branta::VerifyStatus::Incomplete => {
        // Show nothing.
    }
}

// Receive.
let payment = PaymentBuilder::new()
    .set_description("Order 1042")
    .add_destination(address, Some(DestinationType::BitcoinAddress))
    .build();
let registered = service.add_payment(&payment, None).await?;
// Store registered.secret with the invoice. Link registered.verify_url.
```

A missing environment uses staging. Pass `BrantaEnvironment::Production` only in production.

`verify` returns `unknown` for an address Branta has not seen, including a raw on-chain address. `incomplete` means the lookup did not finish (5xx, 429, or no network). `tampered` means a destination decrypted to a different value than the one that was scanned.

`add_payment` encrypts a copy. The `Payment` you built stays plaintext, so a failed post can be retried. Bitcoin addresses use the returned secret. bolt11, Ark, and silent-payment destinations use a key derived from the value. An unset TTL is left off the request so the server applies its 7-day default.

Parent platforms that share one API key call `PaymentBuilder::set_child_platform`. Per-client HMAC keys are still accepted on `BrantaApiOptions.hmac_secret`.

# Development

```bash
cargo test
cargo clippy --all-targets -- -D warnings
BRANTA_RUN_INTEGRATION=1 cargo test --test integration_test
```
