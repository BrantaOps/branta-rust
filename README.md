# Branta Rust SDK

Rust SDK for the [Branta](https://developer.branta.pro) V2 API.

Use `verify` on send and `add_payment` on receive. Status handling and parent platforms are in the [developer docs](https://developer.branta.pro).

## Requirements

Rust 1.75 or higher, with [Tokio](https://tokio.rs).

## Install

```bash
cargo add branta@4.4.0
```

## Send

```rust
use branta::{BrantaApiOptions, BrantaEnvironment, BrantaService};

let service = BrantaService::new(
    BrantaApiOptions::new(BrantaEnvironment::Production), // Staging everywhere else
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
        // 5xx, 429, unreachable, timeout, or malformed lookup. Tell the user.
    }
}
```

On-chain Bitcoin needs a `bitcoin:` URI with `branta_id` and `branta_secret`. EVM USDT and USDC (Ethereum, Polygon, BNB Smart Chain, Base, Arbitrum) verify as an ERC-681 transfer, `ethereum:<contract>@<chainId>/transfer?address=<deposit>`, with `branta_id` and `branta_secret`. The chain id and token contract select one destination type, and `uint256` is not bound. The `pol:`, `eth:`, `bsc:`, `tron:`, `ton:`, and `sol:` schemes do not verify. bolt11, Ark, and silent payments resolve from the value. A bare address, including testnet `tb1` / `bcrt1` and bare `0x`, is `unknown`.

A 404 is `unknown`. 5xx, 429, no network, a timeout, or a malformed GET body is `incomplete`.

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
    // Stablecoins: pass the rail type explicitly — bare addresses are not auto-detected.
    // .add_destination("0x…", Some(DestinationType::UsdtBase))
    // .add_destination("0x…", Some(DestinationType::UsdcArbitrum))
    .set_ttl(600) // seconds
    .build();

let added = service.add_payment(&payment, None).await?;
```

`add_payment` encrypts a copy. The `Payment` you pass in stays plaintext, so a failed post can be retried.

Store `added.secret` with the invoice. Put `branta_id` and `branta_secret` on the invoice QR (`bitcoin:…` or an ERC-681 `ethereum:…/transfer` URI). `added.verify_url` is the link for the wallet.

A parent platform with one shared key sets `api_key` on the service and calls `set_child_platform` for each payment. That is the path for new parent platforms. The deprecated per-client HMAC path is in the developer docs.

## Destination types

`add_payment` accepts `bitcoin_address`, `bolt11`, `ark_address`, `silent_payment`, `usdt_polygon`, `usdc_polygon`, `usdt_ethereum`, `usdc_ethereum`, `usdt_bsc`, `usdc_bsc`, `usdt_base`, `usdc_base`, `usdt_arbitrum`, `usdc_arbitrum`, `usdt_tron`, `usdt_ton`, `usdt_solana`, and `usdc_solana`. Bitcoin and stablecoin addresses use the returned secret. bolt11, Ark, and silent payments use a key derived from the lowercased value, so the same input always produces the same lookup token. Pass stablecoin types explicitly — a bare address is not auto-detected. `usdt_tron`, `usdt_ton`, `usdt_solana`, and `usdc_solana` encrypt on `add_payment` but have no verify URI yet. `usdc_ton` is not available yet.

## Development

```bash
cargo test
cargo clippy --all-targets -- -D warnings
BRANTA_RUN_INTEGRATION=1 BRANTA_API_KEY=… cargo test --test integration_test staging_
```
