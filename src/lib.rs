//! Rust SDK for the Branta V2 API.
//!
//! Use [`BrantaService::verify`] on send and [`BrantaService::add_payment`] on receive.
//! Status handling and parent platforms are in the [developer docs](https://developer.branta.pro).

mod enums;
mod error;
mod extensions;
mod models;
mod options;
mod v2;

pub use enums::{
    is_polygon_evm_destination_type, is_secret_key_address_type, secret_key_uri_family,
    BrantaEnvironment, DestinationType, VerifyStatus, BSC_EVM_DESTINATION_TYPES,
    ETHEREUM_EVM_DESTINATION_TYPES, POLYGON_EVM_DESTINATION_TYPES, SECRET_KEY_URI_FAMILIES,
    SOLANA_DESTINATION_TYPES, TON_DESTINATION_TYPES, TRON_DESTINATION_TYPES,
};
pub use error::BrantaError;
pub use models::{AddPaymentResult, Destination, Payment, Platform, VerifyResult};
pub use options::BrantaApiOptions;
pub use v2::{BrantaService, PaymentBuilder};
