//! Consumer-surface lock. Family helpers stay crate-private; this file only
//! compiles against the public crate root (mirrors the other SDKs' public-API tests).

use branta::{
    BrantaApiOptions, BrantaEnvironment, BrantaError, BrantaService, DestinationType, Payment,
    PaymentBuilder, Platform, VerifyResult, VerifyStatus,
};

#[test]
fn consumer_types_are_reachable() {
    // Eighteen DestinationType variants; usdc_ton stays deferred.
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
        DestinationType::UsdtBase,
        DestinationType::UsdcBase,
        DestinationType::UsdtArbitrum,
        DestinationType::UsdcArbitrum,
    ];
    assert_eq!(all.len(), 18);
    assert_eq!(
        serde_json::to_string(&DestinationType::UsdtBase).unwrap(),
        "\"usdt_base\""
    );
    assert_eq!(
        serde_json::to_string(&DestinationType::UsdcArbitrum).unwrap(),
        "\"usdc_arbitrum\""
    );
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

    let branded = PaymentBuilder::new()
        .set_brand("Acme", Some("https://example.com/logo.png".into()), None)
        .build();
    let brand: &Platform = branded.brand.as_ref().expect("set_brand writes brand");
    assert_eq!(brand.name.as_deref(), Some("Acme"));
    assert_eq!(
        serde_json::to_value(&branded).unwrap()["brand"]["name"],
        "Acme"
    );
    assert!(serde_json::to_value(&branded)
        .unwrap()
        .get("child_platform")
        .is_none());

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
        "EVM_TOKEN_RAILS",
        "EvmTokenRail",
        "evm_token_type",
        "SECRET_KEY_URI_FAMILIES",
        "secret_key_uri_family",
        "is_secret_key_address_type",
        "POLYGON_EVM_DESTINATION_TYPES",
        "ETHEREUM_EVM_DESTINATION_TYPES",
        "BSC_EVM_DESTINATION_TYPES",
        "TRON_DESTINATION_TYPES",
        "TON_DESTINATION_TYPES",
        "SOLANA_DESTINATION_TYPES",
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

#[test]
#[allow(deprecated)]
fn deprecated_child_platform_names_still_work() {
    let old = PaymentBuilder::new()
        .set_child_platform("Acme", None, None)
        .build();
    assert_eq!(old.brand.as_ref().unwrap().name.as_deref(), Some("Acme"));

    let literal = Payment {
        child_platform: Some(Platform {
            name: Some("Acme".into()),
            ..Platform::default()
        }),
        ..Payment::default()
    };
    let json = serde_json::to_value(&literal).unwrap();
    assert_eq!(json["brand"]["name"], "Acme");
    assert!(json.get("child_platform").is_none());

    let parsed: Payment = serde_json::from_str(r#"{"child_platform":{"name":"Acme"}}"#).unwrap();
    assert_eq!(parsed.brand.as_ref().unwrap().name.as_deref(), Some("Acme"));
    assert_eq!(parsed.child_platform, parsed.brand);
}
