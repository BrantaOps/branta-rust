# Branta Rust SDK

Rust SDK for the [Branta](https://developer.branta.pro) V2 API.

Status handling and parent platforms are in the [developer docs](https://developer.branta.pro).

## Install

```bash
cargo add branta
```

## Send

```rust
use branta::{BrantaApiOptions, BrantaEnvironment, BrantaService};

let service = BrantaService::new(
    BrantaApiOptions::new(BrantaEnvironment::Production),
);

let result = service.verify(input, None).await?; // scanned QR or pasted text

match result.status {
    branta::VerifyStatus::Match => {
        // Show the card for result.payments[0]. Link it to result.verify_url.
        // Pay from result.matched_destinations. For an ERC-681 stablecoin scan, the
        // token is on matched_destinations[i].r#type.
    }
    branta::VerifyStatus::Unknown => {
        // Not in Branta. Show nothing.
    }
    branta::VerifyStatus::Tampered => {
        // Destination was altered. Warn. Do not show a verified card.
    }
    branta::VerifyStatus::Incomplete => {
        // Branta could not complete the check. Tell the user. Do not block send.
    }
}
```

Rules for each status: [Status rules](https://developer.branta.pro/setup/send/status-rules). Supported types: [Destination types](https://developer.branta.pro/destination-types).

## Receive

```rust
use branta::{
    BrantaApiOptions, BrantaEnvironment, BrantaService, DestinationType, PaymentBuilder,
};

let mut options = BrantaApiOptions::new(BrantaEnvironment::Production);
options.api_key = Some("<api-key>".into());
let service = BrantaService::new(options);

let payment = PaymentBuilder::new()
    .set_description("Invoice #12345")
    .add_destination("bc1q…", Some(DestinationType::BitcoinAddress))
    .set_ttl(600) // seconds
    .build();

let added = service.add_payment(&payment, None).await?;
// Store added.secret with the invoice. Put branta_id and branta_secret on the QR.
// Link the sender to added.verify_url.
```

`add_payment` accepts the types on [Destination types](https://developer.branta.pro/destination-types). Pass the type for stablecoins. A bare address is not auto-detected. `usdt_tron`, `usdt_ton`, `usdt_solana`, and `usdc_solana` also encrypt and post, but no URI verifies them.