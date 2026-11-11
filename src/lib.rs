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
    is_polygon_evm_destination_type, is_secret_key_address_type, BrantaEnvironment,
    DestinationType, VerifyStatus, POLYGON_EVM_DESTINATION_TYPES,
};
pub use error::BrantaError;
pub use models::{AddPaymentResult, Destination, Payment, Platform, VerifyResult};
pub use options::BrantaApiOptions;
pub use v2::{BrantaService, PaymentBuilder};
