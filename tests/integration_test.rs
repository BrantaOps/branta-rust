//! Live lookups against the same example QR codes as the Go SDK.
//!
//! Skipped unless `BRANTA_RUN_INTEGRATION=1`.

use branta::{BrantaApiOptions, BrantaEnvironment, BrantaService, VerifyStatus};

fn skip_integration() -> bool {
    std::env::var("BRANTA_RUN_INTEGRATION").ok().as_deref() != Some("1")
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
    } else {
        assert!(result.payments.is_empty());
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
    ];
    for (qr, status) in cases {
        check(BrantaEnvironment::Staging, qr, status).await;
    }
}
