//! Live lookups against the same example QR codes as the Go SDK.
//!
//! Skipped unless `BRANTA_RUN_INTEGRATION=1`.
//! Write tests (polygon round-trips / combos) also need `BRANTA_API_KEY`.

use branta::{
    BrantaApiOptions, BrantaEnvironment, BrantaService, DestinationType, PaymentBuilder,
    VerifyStatus,
};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};

fn skip_integration() -> bool {
    std::env::var("BRANTA_RUN_INTEGRATION").ok().as_deref() != Some("1")
}

fn skip_write() -> bool {
    skip_integration()
        || std::env::var("BRANTA_API_KEY")
            .ok()
            .filter(|v| !v.is_empty())
            .is_none()
}

fn service(environment: BrantaEnvironment) -> BrantaService {
    let mut options = BrantaApiOptions::new(environment);
    options.api_key = std::env::var("BRANTA_API_KEY").ok();
    let token = std::env::var("BRANTA_INTEGRATION_METRICS_TOKEN").ok();
    BrantaService::new_with_token(options, token)
}

fn pol_uri(recipient: &str, encrypted: &str, secret: &str) -> String {
    let query = format!(
        "value=50&user=send&currency=USD&branta_id={}&branta_secret={}",
        utf8_percent_encode(encrypted, NON_ALPHANUMERIC),
        utf8_percent_encode(secret, NON_ALPHANUMERIC),
    );
    format!("pol:{recipient}?{query}")
}

async fn check(environment: BrantaEnvironment, qr: &str, status: VerifyStatus) {
    if skip_integration() {
        return;
    }
    let result = service(environment).verify(qr, None).await.unwrap();
    assert_eq!(result.status, status);
    assert!(!result.verify_url.is_empty());
    if status == VerifyStatus::Match {
        assert!(!result.payments.is_empty());
        assert!(!result.matched_destinations.is_empty());
    } else {
        assert!(result.payments.is_empty());
        assert!(result.matched_destinations.is_empty());
    }
    if status == VerifyStatus::Tampered {
        assert!(!result.verify_url.contains('#'));
    }
}

#[tokio::test]
async fn production_example_qr_codes() {
    let cases = [
        (
            "bitcoin:bc1qu3k6geqdjncaarsu2vq56tt8php5vsug9kasmq",
            VerifyStatus::Unknown,
        ),
        (
            "lightning:lnbc17760n1p4r4tqupp5yuapqmxldkc8smuwa6t8shkdg9gezulu0vc7htepfsvweph8kqfsdphgfexzmn5vysygetkv4kx7ur9wgsyc6t8dp6xu6twvusy27rpd4cxcegcqzzsxq97zvuqsp53564rg6w4xjqy7jamcfqxyy83a0j8nzfs0wpevs37t5ln49q6hrs9qxpqysgq47hpqmv34g25le8sceq9jdvul2nz7ucyu0vucv56nlfe40x7n3jsu8duxjrn6tgvdspt872crk9zeatafznm9c57m039z7wyx6g3njsqkchkdh",
            VerifyStatus::Match,
        ),
        (
            "bitcoin:bc1q6745z6cy3u0k9nprurh3x804c4r7u3u8vxca2n?branta_id=Qy4e3KJ9yRs%2BVWq59aSTC6o%2F6vbCnw0v7ZutEs1mxjpGM2i5DgVVl7G0TwFO9CqQ1ws3zNqogQu%2B2%2Bx3U%2BQ8%2FSZtwgjezw%3D%3D&branta_secret=f9b0fd20-b402-4cd2-b68f-3ae3db52dbf5",
            VerifyStatus::Match,
        ),
        (
            "lightning:lnbc17760n1p4r4flypp5k56kq3v2935rl3glkqu9vngfueud2zj87hjcff3t0kn0yrge0pfqdzjgfexzmn5vysz6gzyv4mx2mr0wpjhygzvd9nksarwd9hxwgz6v4ex7gztdehhwmr9v3nk2gz90psk6urvv5cqzzsxq97zvuqsp5hut3t0l0s5mvp9yr06v4253kqtf452z6c65s6g9sga445hc03v6s9qxpqysgqqm430zkk9uymjgvllr3aha88hc6q59etxasfqswn8r8pfm3dstlpp46azv906xtcj3wzprxup5fxn65a5wymt7zzq9sw9qdzx8rgdhcpk80nrg",
            VerifyStatus::Match,
        ),
        (
            "bitcoin:bc1qu3k6geqdjncaarsu2vq56tt8php5vsug9kasmq?lightning=lnbc17760n1p4r4tqupp5yuapqmxldkc8smuwa6t8shkdg9gezulu0vc7htepfsvweph8kqfsdphgfexzmn5vysygetkv4kx7ur9wgsyc6t8dp6xu6twvusy27rpd4cxcegcqzzsxq97zvuqsp53564rg6w4xjqy7jamcfqxyy83a0j8nzfs0wpevs37t5ln49q6hrs9qxpqysgq47hpqmv34g25le8sceq9jdvul2nz7ucyu0vucv56nlfe40x7n3jsu8duxjrn6tgvdspt872crk9zeatafznm9c57m039z7wyx6g3njsqkchkdh&branta_id=%2BbcErHkjD6aDfvhegd1CPRgQQwes64aMIqPXCRBVKP88d982zJt7TUHTq%2B11O9ij9HFzXC%2BTvh%2ByFoECrvZKpv%2FVuGGLIA%3D%3D&branta_secret=c4ba0501-059e-459b-9b11-64d97f158291",
            VerifyStatus::Match,
        ),
        (
            "bitcoin:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            VerifyStatus::Unknown,
        ),
        (
            "bitcoin:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4?branta_id=Qy4e3KJ9yRs%2BVWq59aSTC6o%2F6vbCnw0v7ZutEs1mxjpGM2i5DgVVl7G0TwFO9CqQ1ws3zNqogQu%2B2%2Bx3U%2BQ8%2FSZtwgjezw%3D%3D&branta_secret=f9b0fd20-b402-4cd2-b68f-3ae3db52dbf5",
            VerifyStatus::Tampered,
        ),
    ];
    for (qr, status) in cases {
        check(BrantaEnvironment::Production, qr, status).await;
    }
}

#[tokio::test]
async fn staging_example_qr_codes() {
    let cases = [
        (
            "bitcoin:bc1qgw3dzmhnyvcswc9r0v0z0ajtp8ulm4nuyeahwr",
            VerifyStatus::Unknown,
        ),
        (
            "lightning:lnbc10u1p4w23tzpp50uc6g4020tt3ffp5xfpp83k0lcv2spytpymuupqrnsj0eth8jqgsdqhgfexzmn5vys8xarpva5kuecxq97zvuqsp5tj2a5fd84lhdddzfqz2lwmjqg7n9gp28yy5vtqd78muyzdt5tmsq9qypsqqcqpf6yv66fkcq609xzk0fcqx82hd7fsjhwrzj8xmq743v5lrtssrj95r94hyeumqeejgqvtxqy7ks7ec0uc5lc5zxg240xtwgzjtwkmh3aqqm8gyny",
            VerifyStatus::Match,
        ),
        (
            "bitcoin:bc1qgw3dzmhnyvcswc9r0v0z0ajtp8ulm4nuyeahwr?branta_id=6SpYCe23r79x0t8rNvmjWqhrg8hen4xz%2FYSXhNJ9HLSYrTRPnm%2BSwAuf6NOKobnwE%2B3MQBNkyTnCtIWpKKX2E9ZUWVedig%3D%3D&branta_secret=05eb145d-b5cb-452a-9256-0bdfd9a15ffa",
            VerifyStatus::Match,
        ),
        (
            "bitcoin:tb1qshra2mlujc9wfscvn4d8aqpyqgxzl55853xg7s?branta_id=fa05KT1L6zIAYx2sHcImF3R5RilwMAXAvx%2F5u2YVBIdvnp30drV7bszFzvpdoA%2FeluN0PXbsxcsD38twzw4%2BL8MFoHxkGQ%3D%3D&branta_secret=0621110e-1ad6-483d-80b6-78697c9f6896",
            VerifyStatus::Match,
        ),
        (
            "ark1qztwuhx7vpytv4dcfeqjsepx3kxstnarelmry2smrfdgt2dv87fas7gtqkk",
            VerifyStatus::Match,
        ),
        (
            "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
            VerifyStatus::Match,
        ),
        (
            "bitcoin:bc1q6745z6cy3u0k9nprurh3x804c4r7u3u8vxca2n?lightning=lnbc10u1p4w23tzpp5s6jc8gvun27un7g7q9kmh2vak78r83766heesd9fepa5s56hrpsqdqhgfexzmn5vys8xarpva5kuecxq97zvuqsp5gt4k9wwdgf85g066a05zrnlkh3jc2ng3mh9mw6yw7z03l4kmqzys9qypsqqcqpf7pk6xjfksy8sqhv24es2qgtp0e88wvt2gdv2zceealhjwh0memhzktgnfhdvzc9a6kt74w5jf5c8v9t20k38snawrgngr0sjw9a58fqqn9lwtq&branta_id=NxkrlFgIvGg6f8YZmFAf8qTUza8nXfn%2Bb9H3W7czFAo5Lp4cSpgRSmJgx7P9vaOYu7lkP6XXKvTshQfkXxxRrxJ%2BE7zdpA%3D%3D&branta_secret=6acf2637-511a-4b89-ba2c-f5914d7e669c",
            VerifyStatus::Match,
        ),
        (
            "bitcoin:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            VerifyStatus::Unknown,
        ),
        (
            "bitcoin:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4?branta_id=6SpYCe23r79x0t8rNvmjWqhrg8hen4xz%2FYSXhNJ9HLSYrTRPnm%2BSwAuf6NOKobnwE%2B3MQBNkyTnCtIWpKKX2E9ZUWVedig%3D%3D&branta_secret=05eb145d-b5cb-452a-9256-0bdfd9a15ffa",
            VerifyStatus::Tampered,
        ),
        (
            "pol:0x278297528c32eCa01295B0d2135984d3442ec963?value=50&user=send&currency=USD&branta_id=4WYE9J4TjNitdX7AL%2Fw7frpYdKGwSKHCS5zpFXl%2FlQGwpsQi4%2Fgv5MxgujPFzYMbIKqg2rtyYGpzJCllEA6Qudbi7lLkiA%3D%3D&branta_secret=c0fab1ee-1526-4efa-b991-9ee138a44cd2",
            VerifyStatus::Match,
        ),
        (
            "pol:0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B?value=50&user=send&currency=USD&branta_id=8rnGGWZcg%2Fg3He1OK6yZ6OLOEyusldwIDaoPImRzWjoUGguyXKotuF8ZlGbCZN9TRqx3PdXjvHDdwffdVvIZxmZ00xJvxA%3D%3D&branta_secret=0515039f-2c31-4467-b62a-4e919079a44e",
            VerifyStatus::Match,
        ),
        (
            "0x278297528c32eCa01295B0d2135984d3442ec963",
            VerifyStatus::Unknown,
        ),
    ];
    for (qr, status) in cases {
        check(BrantaEnvironment::Staging, qr, status).await;
    }
}

#[tokio::test]
async fn staging_usdt_polygon_round_trip() {
    if skip_write() {
        return;
    }
    let address = "0x278297528c32eCa01295B0d2135984d3442ec963";
    let swapped = "0x1111111111111111111111111111111111111111";
    let svc = service(BrantaEnvironment::Staging);
    let added = svc
        .add_payment(
            &PaymentBuilder::new()
                .add_destination(address, Some(DestinationType::UsdtPolygon))
                .set_ttl(120)
                .build(),
            None,
        )
        .await
        .unwrap();
    let encrypted = &added.payment.destinations[0].value;
    assert_eq!(
        added.payment.destinations[0].r#type,
        Some(DestinationType::UsdtPolygon)
    );

    let match_result = svc
        .verify(&pol_uri(address, encrypted, &added.secret), None)
        .await
        .unwrap();
    assert_eq!(match_result.status, VerifyStatus::Match);
    assert_eq!(
        match_result.payments[0].destinations[0].r#type,
        Some(DestinationType::UsdtPolygon)
    );
    assert!(match_result.payments[0].destinations[0]
        .value
        .eq_ignore_ascii_case(address));
    assert_eq!(match_result.matched_destinations.len(), 1);
    assert_eq!(
        match_result.matched_destinations[0].r#type,
        Some(DestinationType::UsdtPolygon)
    );

    let lower = svc
        .verify(
            &pol_uri(&address.to_ascii_lowercase(), encrypted, &added.secret),
            None,
        )
        .await
        .unwrap();
    assert_eq!(lower.status, VerifyStatus::Match);

    let tampered = svc
        .verify(&pol_uri(swapped, encrypted, &added.secret), None)
        .await
        .unwrap();
    assert_eq!(tampered.status, VerifyStatus::Tampered);

    let bare = svc.verify(address, None).await.unwrap();
    assert_eq!(bare.status, VerifyStatus::Unknown);

    let pol_bare = svc
        .verify(&format!("pol:{address}?value=50&currency=USD"), None)
        .await
        .unwrap();
    assert_eq!(pol_bare.status, VerifyStatus::Unknown);
}

#[tokio::test]
async fn staging_usdc_polygon_round_trip() {
    if skip_write() {
        return;
    }
    let address = "0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B";
    let swapped = "0x1111111111111111111111111111111111111111";
    let svc = service(BrantaEnvironment::Staging);
    let added = svc
        .add_payment(
            &PaymentBuilder::new()
                .add_destination(address, Some(DestinationType::UsdcPolygon))
                .set_ttl(120)
                .build(),
            None,
        )
        .await
        .unwrap();
    let encrypted = &added.payment.destinations[0].value;

    let match_result = svc
        .verify(&pol_uri(address, encrypted, &added.secret), None)
        .await
        .unwrap();
    assert_eq!(match_result.status, VerifyStatus::Match);
    assert_eq!(
        match_result.matched_destinations[0].r#type,
        Some(DestinationType::UsdcPolygon)
    );
    assert!(match_result.payments[0].destinations[0]
        .value
        .eq_ignore_ascii_case(address));

    let lower = svc
        .verify(
            &pol_uri(&address.to_ascii_lowercase(), encrypted, &added.secret),
            None,
        )
        .await
        .unwrap();
    assert_eq!(lower.status, VerifyStatus::Match);

    let tampered = svc
        .verify(&pol_uri(swapped, encrypted, &added.secret), None)
        .await
        .unwrap();
    assert_eq!(tampered.status, VerifyStatus::Tampered);

    let bare = svc.verify(address, None).await.unwrap();
    assert_eq!(bare.status, VerifyStatus::Unknown);

    let pol_bare = svc
        .verify(&format!("pol:{address}?value=50&currency=USD"), None)
        .await
        .unwrap();
    assert_eq!(pol_bare.status, VerifyStatus::Unknown);
}

#[tokio::test]
async fn staging_live_combos() {
    if skip_write() {
        return;
    }
    let svc = service(BrantaEnvironment::Staging);
    let btc = "bc1qgw3dzmhnyvcswc9r0v0z0ajtp8ulm4nuyeahwr";
    let usdt = "0x278297528c32eCa01295B0d2135984d3442ec963";
    let usdc = "0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B";
    let swap = "0x1111111111111111111111111111111111111111";
    let btc_sw = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

    let added = svc
        .add_payment(
            &PaymentBuilder::new()
                .add_destination(btc, Some(DestinationType::BitcoinAddress))
                .set_ttl(120)
                .build(),
            None,
        )
        .await
        .unwrap();
    let enc = &added.payment.destinations[0].value;
    let qr = format!(
        "bitcoin:{btc}?branta_id={}&branta_secret={}",
        utf8_percent_encode(enc, NON_ALPHANUMERIC),
        utf8_percent_encode(&added.secret, NON_ALPHANUMERIC),
    );
    let match_result = svc.verify(&qr, None).await.unwrap();
    assert_eq!(match_result.status, VerifyStatus::Match);
    assert_eq!(match_result.matched_destinations.len(), 1);
    assert_eq!(
        match_result.matched_destinations[0].r#type,
        Some(DestinationType::BitcoinAddress)
    );
    let swapped_qr = format!(
        "bitcoin:{btc_sw}?branta_id={}&branta_secret={}",
        utf8_percent_encode(enc, NON_ALPHANUMERIC),
        utf8_percent_encode(&added.secret, NON_ALPHANUMERIC),
    );
    assert_eq!(
        svc.verify(&swapped_qr, None).await.unwrap().status,
        VerifyStatus::Tampered
    );
    assert_eq!(
        svc.verify(&format!("bitcoin:{btc}"), None)
            .await
            .unwrap()
            .status,
        VerifyStatus::Unknown
    );

    let added = svc
        .add_payment(
            &PaymentBuilder::new()
                .add_destination(usdt, Some(DestinationType::UsdtPolygon))
                .add_destination(usdc, Some(DestinationType::UsdcPolygon))
                .set_ttl(120)
                .build(),
            None,
        )
        .await
        .unwrap();
    let mut enc_usdt = String::new();
    let mut enc_usdc = String::new();
    for destination in &added.payment.destinations {
        match destination.r#type {
            Some(DestinationType::UsdtPolygon) => enc_usdt = destination.value.clone(),
            Some(DestinationType::UsdcPolygon) => enc_usdc = destination.value.clone(),
            _ => {}
        }
    }
    let usdt_match = svc
        .verify(&pol_uri(usdt, &enc_usdt, &added.secret), None)
        .await
        .unwrap();
    assert_eq!(usdt_match.status, VerifyStatus::Match);
    assert_eq!(usdt_match.matched_destinations.len(), 1);
    assert_eq!(
        usdt_match.matched_destinations[0].r#type,
        Some(DestinationType::UsdtPolygon)
    );
    let usdc_match = svc
        .verify(&pol_uri(usdc, &enc_usdc, &added.secret), None)
        .await
        .unwrap();
    assert_eq!(usdc_match.status, VerifyStatus::Match);
    assert_eq!(usdc_match.matched_destinations.len(), 1);
    assert_eq!(
        usdc_match.matched_destinations[0].r#type,
        Some(DestinationType::UsdcPolygon)
    );

    let added = svc
        .add_payment(
            &PaymentBuilder::new()
                .add_destination(usdt, Some(DestinationType::UsdtPolygon))
                .add_destination(usdt, Some(DestinationType::UsdcPolygon))
                .set_ttl(120)
                .build(),
            None,
        )
        .await
        .unwrap();
    let enc = &added.payment.destinations[0].value;
    let both = svc
        .verify(&pol_uri(usdt, enc, &added.secret), None)
        .await
        .unwrap();
    assert_eq!(both.status, VerifyStatus::Match);
    assert_eq!(both.matched_destinations.len(), 2);

    let added = svc
        .add_payment(
            &PaymentBuilder::new()
                .add_destination(btc, Some(DestinationType::BitcoinAddress))
                .add_destination(usdt, Some(DestinationType::UsdtPolygon))
                .set_ttl(120)
                .build(),
            None,
        )
        .await
        .unwrap();
    let mut enc_btc = String::new();
    let mut enc_usdt = String::new();
    for destination in &added.payment.destinations {
        match destination.r#type {
            Some(DestinationType::BitcoinAddress) => enc_btc = destination.value.clone(),
            Some(DestinationType::UsdtPolygon) => enc_usdt = destination.value.clone(),
            _ => {}
        }
    }
    let btc_qr = format!(
        "bitcoin:{btc}?branta_id={}&branta_secret={}",
        utf8_percent_encode(&enc_btc, NON_ALPHANUMERIC),
        utf8_percent_encode(&added.secret, NON_ALPHANUMERIC),
    );
    let btc_match = svc.verify(&btc_qr, None).await.unwrap();
    assert_eq!(btc_match.status, VerifyStatus::Match);
    assert_eq!(btc_match.matched_destinations.len(), 1);
    assert_eq!(
        btc_match.matched_destinations[0].r#type,
        Some(DestinationType::BitcoinAddress)
    );
    let pol_match = svc
        .verify(&pol_uri(usdt, &enc_usdt, &added.secret), None)
        .await
        .unwrap();
    assert_eq!(pol_match.status, VerifyStatus::Match);
    assert_eq!(pol_match.matched_destinations.len(), 1);
    assert_eq!(
        pol_match.matched_destinations[0].r#type,
        Some(DestinationType::UsdtPolygon)
    );
    assert_eq!(
        svc.verify(&pol_uri(swap, &enc_usdt, &added.secret), None)
            .await
            .unwrap()
            .status,
        VerifyStatus::Tampered
    );

    let added = svc
        .add_payment(
            &PaymentBuilder::new()
                .add_destination(usdt, Some(DestinationType::UsdtPolygon))
                .set_ttl(120)
                .build(),
            None,
        )
        .await
        .unwrap();
    let enc = &added.payment.destinations[0].value;
    assert_eq!(
        svc.verify(
            &pol_uri(&usdt.to_ascii_lowercase(), enc, &added.secret),
            None
        )
        .await
        .unwrap()
        .status,
        VerifyStatus::Match
    );
    assert_eq!(
        svc.verify(
            &pol_uri(usdt, enc, "00000000-0000-0000-0000-000000000000"),
            None
        )
        .await
        .unwrap()
        .status,
        VerifyStatus::Unknown
    );
    assert_eq!(
        svc.verify(usdt, None).await.unwrap().status,
        VerifyStatus::Unknown
    );
    assert_eq!(
        svc.verify(&format!("pol:{usdt}?value=50&currency=USD"), None)
            .await
            .unwrap()
            .status,
        VerifyStatus::Unknown
    );
}

fn secret_key_uri(scheme: &str, recipient: &str, encrypted: &str, secret: &str) -> String {
    let query = format!(
        "branta_id={}&branta_secret={}",
        utf8_percent_encode(encrypted, NON_ALPHANUMERIC),
        utf8_percent_encode(secret, NON_ALPHANUMERIC),
    );
    format!("{scheme}:{recipient}?{query}")
}

struct SecretKeyRail {
    name: &'static str,
    destination_type: DestinationType,
    scheme: &'static str,
    address: &'static str,
    swapped: &'static str,
    case_fold: bool,
}

fn secret_key_rails() -> Vec<SecretKeyRail> {
    vec![
        SecretKeyRail {
            name: "bitcoin",
            destination_type: DestinationType::BitcoinAddress,
            scheme: "bitcoin",
            address: "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
            swapped: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            case_fold: false,
        },
        SecretKeyRail {
            name: "usdt_polygon",
            destination_type: DestinationType::UsdtPolygon,
            scheme: "pol",
            address: "0x278297528c32eCa01295B0d2135984d3442ec963",
            swapped: "0x1111111111111111111111111111111111111111",
            case_fold: true,
        },
        SecretKeyRail {
            name: "usdc_polygon",
            destination_type: DestinationType::UsdcPolygon,
            scheme: "pol",
            address: "0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B",
            swapped: "0x2222222222222222222222222222222222222222",
            case_fold: true,
        },
        SecretKeyRail {
            name: "usdt_ethereum",
            destination_type: DestinationType::UsdtEthereum,
            scheme: "eth",
            address: "0xBF5550253939187432Ef4dccE8089765d3DCb47f",
            swapped: "0x3333333333333333333333333333333333333333",
            case_fold: true,
        },
        SecretKeyRail {
            name: "usdc_ethereum",
            destination_type: DestinationType::UsdcEthereum,
            scheme: "eth",
            address: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            swapped: "0x4444444444444444444444444444444444444444",
            case_fold: true,
        },
        SecretKeyRail {
            name: "usdt_bsc",
            destination_type: DestinationType::UsdtBsc,
            scheme: "bsc",
            address: "0x55d398326f99059fF775485246999027B3197955",
            swapped: "0x5555555555555555555555555555555555555555",
            case_fold: true,
        },
        SecretKeyRail {
            name: "usdc_bsc",
            destination_type: DestinationType::UsdcBsc,
            scheme: "bsc",
            address: "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d",
            swapped: "0x6666666666666666666666666666666666666666",
            case_fold: true,
        },
        SecretKeyRail {
            name: "usdt_tron",
            destination_type: DestinationType::UsdtTron,
            scheme: "tron",
            address: "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb",
            swapped: "TXyZ1111111111111111111111111111111",
            case_fold: false,
        },
        SecretKeyRail {
            name: "usdt_ton",
            destination_type: DestinationType::UsdtTon,
            scheme: "ton",
            address: "EQDtFpEwcFAEcRe5mLVh2N6C0y-_tur3BYOM93pEZPw390by",
            swapped: "EQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM9c",
            case_fold: false,
        },
        SecretKeyRail {
            name: "usdt_solana",
            destination_type: DestinationType::UsdtSolana,
            scheme: "sol",
            address: "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB",
            swapped: "11111111111111111111111111111111",
            case_fold: false,
        },
        SecretKeyRail {
            name: "usdc_solana",
            destination_type: DestinationType::UsdcSolana,
            scheme: "sol",
            address: "7EqQdEULxWcraVx3mXKFjc84LhCkMGZCkRuDofycyinf",
            swapped: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            case_fold: false,
        },
    ]
}

/// Live staging add_payment → verify for every secret-key rail.
#[tokio::test]
async fn staging_secret_key_round_trip() {
    if skip_write() {
        return;
    }
    let svc = service(BrantaEnvironment::Staging);
    for rail in secret_key_rails() {
        let added = svc
            .add_payment(
                &PaymentBuilder::new()
                    .add_destination(rail.address, Some(rail.destination_type))
                    .set_ttl(120)
                    .build(),
                None,
            )
            .await
            .unwrap_or_else(|err| panic!("{} add_payment: {err}", rail.name));
        let encrypted = &added.payment.destinations[0].value;
        assert_eq!(
            added.payment.destinations[0].r#type,
            Some(rail.destination_type),
            "{}",
            rail.name
        );

        let match_result = svc
            .verify(
                &secret_key_uri(rail.scheme, rail.address, encrypted, &added.secret),
                None,
            )
            .await
            .unwrap();
        assert_eq!(match_result.status, VerifyStatus::Match, "{}", rail.name);
        assert_eq!(match_result.matched_destinations.len(), 1, "{}", rail.name);
        assert_eq!(
            match_result.matched_destinations[0].r#type,
            Some(rail.destination_type),
            "{}",
            rail.name
        );
        if rail.case_fold {
            assert!(
                match_result.matched_destinations[0]
                    .value
                    .eq_ignore_ascii_case(rail.address),
                "{}",
                rail.name
            );
            let lower = svc
                .verify(
                    &secret_key_uri(
                        rail.scheme,
                        &rail.address.to_ascii_lowercase(),
                        encrypted,
                        &added.secret,
                    ),
                    None,
                )
                .await
                .unwrap();
            assert_eq!(lower.status, VerifyStatus::Match, "{}", rail.name);
        } else {
            assert_eq!(
                match_result.matched_destinations[0].value, rail.address,
                "{}",
                rail.name
            );
        }

        let tampered = svc
            .verify(
                &secret_key_uri(rail.scheme, rail.swapped, encrypted, &added.secret),
                None,
            )
            .await
            .unwrap();
        assert_eq!(tampered.status, VerifyStatus::Tampered, "{}", rail.name);

        let bare = svc.verify(rail.address, None).await.unwrap();
        assert_eq!(bare.status, VerifyStatus::Unknown, "{}", rail.name);
    }
}
