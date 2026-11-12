//! Consumer-surface lock. Family helpers stay crate-private; this file only
//! compiles against the public crate root (mirror Kotlin/Swift/Go/dotnet).

use branta::{
    BrantaApiOptions, BrantaEnvironment, BrantaError, BrantaService, DestinationType,
    PaymentBuilder, VerifyResult, VerifyStatus,
};

#[test]
fn consumer_types_are_reachable() {
    // Fourteen DestinationType variants; usdc_ton stays deferred.
    let all = [
        DestinationType::BitcoinAddress,
        DestinationType::Bolt11,
        DestinationType::ArkAddress,
        DestinationType::SilentPayment,
        DestinationType::UsdtPolygon,
        DestinationType::UsdcPolygon,
        DestinationType::UsdtEthereum,
        DestinationType::UsdcEthereum,
        DestinationType::UsdtBsc,
        DestinationType::UsdcBsc,
        DestinationType::UsdtTron,
        DestinationType::UsdtTon,
        DestinationType::UsdtSolana,
        DestinationType::UsdcSolana,
    ];
    assert_eq!(all.len(), 14);
    assert_eq!(
        serde_json::to_string(&DestinationType::UsdtEthereum).unwrap(),
        "\"usdt_ethereum\""
    );
    assert_eq!(
        serde_json::to_string(&DestinationType::UsdcSolana).unwrap(),
        "\"usdc_solana\""
    );
    assert_eq!(
        serde_json::to_string(&DestinationType::UsdtTon).unwrap(),
        "\"usdt_ton\""
    );
    assert!(serde_json::from_str::<DestinationType>("\"usdc_ton\"").is_err());

    assert_eq!(VerifyStatus::Match.as_str(), "match");
    assert_eq!(
        BrantaEnvironment::Staging.url(),
        "https://staging.guardrail.branta.pro"
    );

    let mut options = BrantaApiOptions::new(BrantaEnvironment::Localhost);
    options.api_key = Some("k".into());
    assert_eq!(options.api_key.as_deref(), Some("k"));

    let service = BrantaService::new(BrantaApiOptions::new(BrantaEnvironment::Staging));
    let _ = service;

    let payment = PaymentBuilder::new()
        .add_destination("bc1qexample", Some(DestinationType::BitcoinAddress))
        .build();
    assert_eq!(payment.destinations.len(), 1);

    let verify = VerifyResult {
        status: VerifyStatus::Unknown,
        payments: Vec::new(),
        verify_url: "https://example/v2/verify/x".into(),
        matched_destinations: Vec::new(),
    };
    assert_eq!(verify.status, VerifyStatus::Unknown);
    assert!(verify.matched_destinations.is_empty());

    let err = BrantaError::LogoUrlDomainMismatch("platform_logo_url".into());
    assert!(err.to_string().contains("platform_logo_url"));
}

#[test]
fn family_helpers_are_not_reexported_from_lib() {
    let lib = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"),
    )
    .expect("src/lib.rs");
    let forbidden = [
        "SECRET_KEY_URI_FAMILIES",
        "is_secret_key_address_type",
        "is_polygon_evm_destination_type",
        "POLYGON_EVM_DESTINATION_TYPES",
        "ETHEREUM_EVM_DESTINATION_TYPES",
        "BSC_EVM_DESTINATION_TYPES",
        "TRON_DESTINATION_TYPES",
        "TON_DESTINATION_TYPES",
        "SOLANA_DESTINATION_TYPES",
        "secret_key_uri_family",
        "BrantaClient",
        "QrParser",
    ];
    for name in forbidden {
        assert!(
            !lib.contains(name),
            "{name} must stay out of the public crate root (src/lib.rs)"
        );
    }
}
