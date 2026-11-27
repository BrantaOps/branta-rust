# Branta Rust SDK

Rust SDK for [Branta](https://developer.branta.pro).

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

### Brand

A platform that signs with a shared `api_key` can tag a payment with the brand (payee) it is for: a name plus optional logo source URLs. The SDK sends it as `brand`, which needs a Branta server that accepts `brand`.

```rust
let payment = PaymentBuilder::new()
    .set_brand("Acme Coffee", Some("https://…/logo.png".into()), None)
    .add_destination("bc1q…", Some(DestinationType::BitcoinAddress))
    .build();
```

`set_child_platform` and `Payment.child_platform` are the deprecated old names. They still work: `set_child_platform` calls `set_brand`, and the SDK never sends `child_platform`. A parsed payload fills `brand` from `brand` or `child_platform` (`brand` wins) and mirrors it into `child_platform`.

### HMAC signing

If Branta enabled Require HMAC on your platform, create a Secret in Guardrail and set it as `hmac_secret`. The service signs each `add_payment`. Keep it server-side. See [HMAC signing](https://developer.branta.pro/setup/receive/hmac-signing).

```rust
let mut options = BrantaApiOptions::new(BrantaEnvironment::Production);
options.api_key = Some("<api-key>".into());
options.hmac_secret = Some("<secret>".into());
let service = BrantaService::new(options);
```