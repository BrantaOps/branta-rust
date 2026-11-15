//! Live lookups against the same example QR codes as the Go SDK.
//!
//! Skipped unless `BRANTA_RUN_INTEGRATION=1`.
//! Write tests (multi-rail round-trips / combos) also need `BRANTA_API_KEY`.

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
            "ethereum:0xc2132d05d31c914a87c6611c10748aeb04b58e8f@137/transfer?address=0x278297528c32eCa01295B0d2135984d3442ec963&uint256=50000000&branta_id=4WYE9J4TjNitdX7AL%2Fw7frpYdKGwSKHCS5zpFXl%2FlQGwpsQi4%2Fgv5MxgujPFzYMbIKqg2rtyYGpzJCllEA6Qudbi7lLkiA%3D%3D&branta_secret=c0fab1ee-1526-4efa-b991-9ee138a44cd2",
            VerifyStatus::Match,
        ),
        (
            "ethereum:0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359@137/transfer?address=0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B&uint256=50000000&branta_id=8rnGGWZcg%2Fg3He1OK6yZ6OLOEyusldwIDaoPImRzWjoUGguyXKotuF8ZlGbCZN9TRqx3PdXjvHDdwffdVvIZxmZ00xJvxA%3D%3D&branta_secret=0515039f-2c31-4467-b62a-4e919079a44e",
            VerifyStatus::Match,
        ),
        (
            "ethereum:0xdAC17F958D2ee523a2206206994597C13D831ec7@1/transfer?address=0xBF5550253939187432Ef4dccE8089765d3DCb47f&uint256=1000000&branta_id=hEdYLfbK2EqIn7Sj3Z7o6MVOcwOtPmA9eup2Xt3b58MzqVmu5RnLKh1WcEn5086MgRznzA7vtdw04YpQo9%2BJPzDATs7MGQ%3D%3D&branta_secret=a8065c37-6728-487e-b94a-58990fa494f4",
            VerifyStatus::Match,
        ),
        (
            "ethereum:0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48@1/transfer?address=0x1111111111111111111111111111111111111112&uint256=1000000&branta_id=kZfmySkTUMNBaltxtHmPwulVBnXTWhPTV%2ByvgbwciaikaJNobP%2BQSO5lnxnhWPp1QiULnzas%2Brh%2FYCZSMotBN2lmbPDI5A%3D%3D&branta_secret=3e8ba7a8-f7b2-4ec5-bd78-aced1e2ec747",
            VerifyStatus::Match,
        ),
        (
            "ethereum:0x55d398326f99059fF775485246999027B3197955@56/transfer?address=0x1111111111111111111111111111111111111113&uint256=1000000000000000000&branta_id=mkuZIr%2BgINAnuduVhc5cj5N3%2FlmqYKntp28Vl4MyEkmI%2F%2BgXFuJ3qCT4TJq4js2UkYVWQMCSa7%2Bc15%2BPqv13ncsqx9daEA%3D%3D&branta_secret=15a81c25-62dc-4dc9-8c45-4aa7965235a1",
            VerifyStatus::Match,
        ),
        (
            "ethereum:0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d@56/transfer?address=0x1111111111111111111111111111111111111114&uint256=1000000000000000000&branta_id=lnOeOCF%2BtcA3WPbDLiKThwXQjGwKXRnKleDRo7vLEpRyvfeb%2BNvH9FIFXv2lppn39%2Bi%2For1aMtA%2F814DjFAg0sH2hARAzw%3D%3D&branta_secret=0edd3453-4249-4d54-aa06-5329b6d506c7",
            VerifyStatus::Match,
        ),
        (
            "ethereum:0xfde4C96c8593536E31F229EA8f37b2ADa2699bb2@8453/transfer?address=0x1111111111111111111111111111111111111115&uint256=1000000&branta_id=vBvqB0uhBi6objCfmXR%2B4cvofi%2FSwC08%2BCANwZrDPFVKfTg24qBWk6xuBoPifgofkUkK8q3n3a3Djh9nb%2Bh%2B8%2FaC%2Bh%2FjVw%3D%3D&branta_secret=5f204ca2-8c06-47ee-b339-8df769ec4988",
            VerifyStatus::Match,
        ),
        (
            "ethereum:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913@8453/transfer?address=0x1111111111111111111111111111111111111116&uint256=1000000&branta_id=4y98sndEJvATBQawsOIcank8PyVpdUhfk2X4Z7FTok6P%2BdsOZE7xY%2F%2FiIbmYFMnEwbLN%2BdcKcX0ipyFg3jKEQcb3zB%2F8XA%3D%3D&branta_secret=82af0fe5-14ce-400d-8a66-22c8bc9f2af8",
            VerifyStatus::Match,
        ),
        (
            "ethereum:0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9@42161/transfer?address=0x1111111111111111111111111111111111111117&uint256=1000000&branta_id=mfFg02EOgLqYr8LHE%2FFUrNtHKsHbKG2qIx8flxggEoYZiYELfgMu67F2BdBsPi9HLQ6PtJPm%2FATA4GxOps2Fgby9jpe1Hg%3D%3D&branta_secret=53d713ad-f65e-4af1-b83c-b9f46500c0d5",
            VerifyStatus::Match,
        ),
        (
            "ethereum:0xaf88d065e77c8cC2239327C5EDb3A432268e5831@42161/transfer?address=0x1111111111111111111111111111111111111118&uint256=1000000&branta_id=SFlYfTXtcslM7BM07KJYow6YzeoijFMpQAsesIRDbphUzXsaHggmMximxaWhv178SssuaxhbDrqHk5KJAqKXqfwKegFpbQ%3D%3D&branta_secret=e7d829e9-18da-4831-aba7-678645e22c95",
            VerifyStatus::Match,
        ),
        (
            "ethereum:0xc2132d05d31c914a87c6611c10748aeb04b58e8f@137/transfer?address=0x2222222222222222222222222222222222222222&uint256=50000000&branta_id=4WYE9J4TjNitdX7AL%2Fw7frpYdKGwSKHCS5zpFXl%2FlQGwpsQi4%2Fgv5MxgujPFzYMbIKqg2rtyYGpzJCllEA6Qudbi7lLkiA%3D%3D&branta_secret=c0fab1ee-1526-4efa-b991-9ee138a44cd2",
            VerifyStatus::Tampered,
        ),
        (
            "ethereum:0xdAC17F958D2ee523a2206206994597C13D831ec7@1/transfer?address=0x2222222222222222222222222222222222222222&uint256=1000000&branta_id=hEdYLfbK2EqIn7Sj3Z7o6MVOcwOtPmA9eup2Xt3b58MzqVmu5RnLKh1WcEn5086MgRznzA7vtdw04YpQo9%2BJPzDATs7MGQ%3D%3D&branta_secret=a8065c37-6728-487e-b94a-58990fa494f4",
            VerifyStatus::Tampered,
        ),
        (
            "ethereum:0x55d398326f99059fF775485246999027B3197955@56/transfer?address=0x2222222222222222222222222222222222222222&uint256=1000000000000000000&branta_id=mkuZIr%2BgINAnuduVhc5cj5N3%2FlmqYKntp28Vl4MyEkmI%2F%2BgXFuJ3qCT4TJq4js2UkYVWQMCSa7%2Bc15%2BPqv13ncsqx9daEA%3D%3D&branta_secret=15a81c25-62dc-4dc9-8c45-4aa7965235a1",
            VerifyStatus::Tampered,
        ),
        (
            "ethereum:0xfde4C96c8593536E31F229EA8f37b2ADa2699bb2@8453/transfer?address=0x2222222222222222222222222222222222222222&uint256=1000000&branta_id=vBvqB0uhBi6objCfmXR%2B4cvofi%2FSwC08%2BCANwZrDPFVKfTg24qBWk6xuBoPifgofkUkK8q3n3a3Djh9nb%2Bh%2B8%2FaC%2Bh%2FjVw%3D%3D&branta_secret=5f204ca2-8c06-47ee-b339-8df769ec4988",
            VerifyStatus::Tampered,
        ),
        (
            "ethereum:0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9@42161/transfer?address=0x2222222222222222222222222222222222222222&uint256=1000000&branta_id=mfFg02EOgLqYr8LHE%2FFUrNtHKsHbKG2qIx8flxggEoYZiYELfgMu67F2BdBsPi9HLQ6PtJPm%2FATA4GxOps2Fgby9jpe1Hg%3D%3D&branta_secret=53d713ad-f65e-4af1-b83c-b9f46500c0d5",
            VerifyStatus::Tampered,
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

/// One EVM stablecoin rail: chain id plus token contract select the destination type.
struct EvmRail {
    name: &'static str,
    destination_type: DestinationType,
    chain_id: u64,
    contract: &'static str,
}

const EVM_RAILS: [EvmRail; 10] = [
    EvmRail {
        name: "usdt_ethereum",
        destination_type: DestinationType::UsdtEthereum,
        chain_id: 1,
        contract: "0xdAC17F958D2ee523a2206206994597C13D831ec7",
    },
    EvmRail {
        name: "usdc_ethereum",
        destination_type: DestinationType::UsdcEthereum,
        chain_id: 1,
        contract: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    },
    EvmRail {
        name: "usdt_polygon",
        destination_type: DestinationType::UsdtPolygon,
        chain_id: 137,
        contract: "0xc2132d05d31c914a87c6611c10748aeb04b58e8f",
    },
    EvmRail {
        name: "usdc_polygon",
        destination_type: DestinationType::UsdcPolygon,
        chain_id: 137,
        contract: "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359",
    },
    EvmRail {
        name: "usdt_bsc",
        destination_type: DestinationType::UsdtBsc,
        chain_id: 56,
        contract: "0x55d398326f99059fF775485246999027B3197955",
    },
    EvmRail {
        name: "usdc_bsc",
        destination_type: DestinationType::UsdcBsc,
        chain_id: 56,
        contract: "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d",
    },
    EvmRail {
        name: "usdt_base",
        destination_type: DestinationType::UsdtBase,
        chain_id: 8453,
        contract: "0xfde4C96c8593536E31F229EA8f37b2ADa2699bb2",
    },
    EvmRail {
        name: "usdc_base",
        destination_type: DestinationType::UsdcBase,
        chain_id: 8453,
        contract: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    },
    EvmRail {
        name: "usdt_arbitrum",
        destination_type: DestinationType::UsdtArbitrum,
        chain_id: 42161,
        contract: "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9",
    },
    EvmRail {
        name: "usdc_arbitrum",
        destination_type: DestinationType::UsdcArbitrum,
        chain_id: 42161,
        contract: "0xaf88d065e77c8cC2239327C5EDb3A432268e5831",
    },
];

const DEPOSIT: &str = "0xAbCdEf0123456789aBcDeF0123456789AbCdEf01";
const SWAPPED_DEPOSIT: &str = "0x1111111111111111111111111111111111111111";

fn encoded(value: &str) -> String {
    utf8_percent_encode(value, NON_ALPHANUMERIC).to_string()
}

fn transfer_uri(rail: &EvmRail, address: &str, encrypted: &str, secret: &str) -> String {
    format!(
        "ethereum:{}@{}/transfer?address={address}&uint256=50000&branta_id={}&branta_secret={}",
        rail.contract,
        rail.chain_id,
        encoded(encrypted),
        encoded(secret),
    )
}

fn bitcoin_uri(address: &str, encrypted: &str, secret: &str) -> String {
    format!(
        "bitcoin:{address}?branta_id={}&branta_secret={}",
        encoded(encrypted),
        encoded(secret),
    )
}

fn payment_for(items: &[(&str, DestinationType)]) -> branta::Payment {
    let mut builder = PaymentBuilder::new();
    for (address, destination_type) in items {
        builder = builder.add_destination(*address, Some(*destination_type));
    }
    builder.set_ttl(120).build()
}

/// Live staging add_payment then verify for every EVM rail.
#[tokio::test]
async fn staging_evm_round_trip() {
    if skip_write() {
        return;
    }
    let svc = service(BrantaEnvironment::Staging);
    for rail in &EVM_RAILS {
        let added = svc
            .add_payment(&payment_for(&[(DEPOSIT, rail.destination_type)]), None)
            .await
            .unwrap_or_else(|err| panic!("{} add_payment: {err}", rail.name));
        let encrypted = &added.payment.destinations[0].value;
        assert_eq!(
            added.payment.destinations[0].r#type,
            Some(rail.destination_type),
            "{}",
            rail.name
        );

        let matched = svc
            .verify(&transfer_uri(rail, DEPOSIT, encrypted, &added.secret), None)
            .await
            .unwrap();
        assert_eq!(matched.status, VerifyStatus::Match, "{}", rail.name);
        assert_eq!(matched.matched_destinations.len(), 1, "{}", rail.name);
        assert_eq!(
            matched.matched_destinations[0].r#type,
            Some(rail.destination_type),
            "{}",
            rail.name
        );
        assert_eq!(
            matched.matched_destinations[0].value, DEPOSIT,
            "{}",
            rail.name
        );

        let lower = svc
            .verify(
                &transfer_uri(
                    rail,
                    &DEPOSIT.to_ascii_lowercase(),
                    encrypted,
                    &added.secret,
                ),
                None,
            )
            .await
            .unwrap();
        assert_eq!(lower.status, VerifyStatus::Match, "{}", rail.name);

        let tampered = svc
            .verify(
                &transfer_uri(rail, SWAPPED_DEPOSIT, encrypted, &added.secret),
                None,
            )
            .await
            .unwrap();
        assert_eq!(tampered.status, VerifyStatus::Tampered, "{}", rail.name);
        assert!(!tampered.verify_url.contains('#'));

        let wrong_secret = svc
            .verify(
                &transfer_uri(
                    rail,
                    DEPOSIT,
                    encrypted,
                    "00000000-0000-0000-0000-000000000000",
                ),
                None,
            )
            .await
            .unwrap();
        assert_eq!(wrong_secret.status, VerifyStatus::Unknown, "{}", rail.name);

        let bare = svc.verify(DEPOSIT, None).await.unwrap();
        assert_eq!(bare.status, VerifyStatus::Unknown, "{}", rail.name);
    }
}

/// Tron, TON, and Solana still encrypt on add_payment. They have no verify URI.
#[tokio::test]
async fn staging_post_only_rails_encrypt() {
    if skip_write() {
        return;
    }
    let svc = service(BrantaEnvironment::Staging);
    let cases = [
        (
            DestinationType::UsdtTron,
            "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb",
        ),
        (
            DestinationType::UsdtTon,
            "EQDtFpEwcFAEcRe5mLVh2N6C0y-_tur3BYOM93pEZPw390by",
        ),
        (
            DestinationType::UsdtSolana,
            "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB",
        ),
        (
            DestinationType::UsdcSolana,
            "7EqQdEULxWcraVx3mXKFjc84LhCkMGZCkRuDofycyinf",
        ),
    ];
    for (destination_type, address) in cases {
        let added = svc
            .add_payment(&payment_for(&[(address, destination_type)]), None)
            .await
            .unwrap_or_else(|err| panic!("{destination_type:?} add_payment: {err}"));
        let posted = &added.payment.destinations[0];
        assert_eq!(posted.r#type, Some(destination_type));
        assert_ne!(posted.value, address);
    }
}

#[tokio::test]
async fn staging_bitcoin_round_trip() {
    if skip_write() {
        return;
    }
    let svc = service(BrantaEnvironment::Staging);
    let btc = "bc1qgw3dzmhnyvcswc9r0v0z0ajtp8ulm4nuyeahwr";
    let swapped = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    let added = svc
        .add_payment(
            &payment_for(&[(btc, DestinationType::BitcoinAddress)]),
            None,
        )
        .await
        .unwrap();
    let enc = &added.payment.destinations[0].value;

    let matched = svc
        .verify(&bitcoin_uri(btc, enc, &added.secret), None)
        .await
        .unwrap();
    assert_eq!(matched.status, VerifyStatus::Match);
    assert_eq!(matched.matched_destinations.len(), 1);
    assert_eq!(
        matched.matched_destinations[0].r#type,
        Some(DestinationType::BitcoinAddress)
    );
    assert_eq!(
        svc.verify(&bitcoin_uri(swapped, enc, &added.secret), None)
            .await
            .unwrap()
            .status,
        VerifyStatus::Tampered
    );
    assert_eq!(
        svc.verify(&format!("bitcoin:{btc}"), None)
            .await
            .unwrap()
            .status,
        VerifyStatus::Unknown
    );
}

#[tokio::test]
async fn staging_live_combos() {
    if skip_write() {
        return;
    }
    let svc = service(BrantaEnvironment::Staging);
    let usdt = &EVM_RAILS[6]; // usdt_base
    let usdc = &EVM_RAILS[7]; // usdc_base
    let polygon = &EVM_RAILS[2]; // usdt_polygon
    let btc = "bc1qgw3dzmhnyvcswc9r0v0z0ajtp8ulm4nuyeahwr";

    // USDT and USDC on the same chain and deposit: each scan binds only its own token.
    let added = svc
        .add_payment(
            &payment_for(&[
                (DEPOSIT, usdt.destination_type),
                (DEPOSIT, usdc.destination_type),
            ]),
            None,
        )
        .await
        .unwrap();
    let cipher_of = |t: DestinationType| {
        added
            .payment
            .destinations
            .iter()
            .find(|d| d.r#type == Some(t))
            .map(|d| d.value.clone())
            .unwrap()
    };
    for rail in [usdt, usdc] {
        let result = svc
            .verify(
                &transfer_uri(
                    rail,
                    DEPOSIT,
                    &cipher_of(rail.destination_type),
                    &added.secret,
                ),
                None,
            )
            .await
            .unwrap();
        assert_eq!(result.status, VerifyStatus::Match, "{}", rail.name);
        assert_eq!(result.matched_destinations.len(), 1, "{}", rail.name);
        assert_eq!(
            result.matched_destinations[0].r#type,
            Some(rail.destination_type),
            "{}",
            rail.name
        );
    }

    // A USDC scan against a USDT-only payment is not a match.
    let added = svc
        .add_payment(&payment_for(&[(DEPOSIT, usdt.destination_type)]), None)
        .await
        .unwrap();
    let usdc_scan = svc
        .verify(
            &transfer_uri(
                usdc,
                DEPOSIT,
                &added.payment.destinations[0].value,
                &added.secret,
            ),
            None,
        )
        .await
        .unwrap();
    assert_eq!(usdc_scan.status, VerifyStatus::Unknown);

    // Bitcoin plus an EVM rail in one payment: each scan binds only its own rail.
    let added = svc
        .add_payment(
            &payment_for(&[
                (btc, DestinationType::BitcoinAddress),
                (DEPOSIT, polygon.destination_type),
            ]),
            None,
        )
        .await
        .unwrap();
    let cipher_of = |t: DestinationType| {
        added
            .payment
            .destinations
            .iter()
            .find(|d| d.r#type == Some(t))
            .map(|d| d.value.clone())
            .unwrap()
    };
    let btc_match = svc
        .verify(
            &bitcoin_uri(
                btc,
                &cipher_of(DestinationType::BitcoinAddress),
                &added.secret,
            ),
            None,
        )
        .await
        .unwrap();
    assert_eq!(btc_match.status, VerifyStatus::Match);
    assert_eq!(btc_match.matched_destinations.len(), 1);
    assert_eq!(
        btc_match.matched_destinations[0].r#type,
        Some(DestinationType::BitcoinAddress)
    );
    let evm_match = svc
        .verify(
            &transfer_uri(
                polygon,
                DEPOSIT,
                &cipher_of(polygon.destination_type),
                &added.secret,
            ),
            None,
        )
        .await
        .unwrap();
    assert_eq!(evm_match.status, VerifyStatus::Match);
    assert_eq!(evm_match.matched_destinations.len(), 1);
    assert_eq!(
        evm_match.matched_destinations[0].r#type,
        Some(polygon.destination_type)
    );
    assert_eq!(
        svc.verify(
            &transfer_uri(
                polygon,
                SWAPPED_DEPOSIT,
                &cipher_of(polygon.destination_type),
                &added.secret
            ),
            None
        )
        .await
        .unwrap()
        .status,
        VerifyStatus::Tampered
    );
}
