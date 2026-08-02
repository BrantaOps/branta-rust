//! Integration tests against live Branta endpoints.
//!
//! These hit real staging/production servers with the exact same example QR-code fixtures used
//! by `branta-python`'s `tests/test_integration.py`, so a payment that resolves there resolves
//! identically here -- genuine cross-SDK confidence rather than each SDK testing against an
//! arbitrary payment of its own. Skipped when `BRANTA_SKIP_INTEGRATION` is set (matching the
//! Python suite's env var name, not a bespoke one), since CI sets that to avoid depending on
//! network access.

use branta::{BrantaClientOptions, BrantaServerBaseUrl, BrantaService, PrivacyMode};

fn skip_integration() -> bool {
    std::env::var("BRANTA_SKIP_INTEGRATION").is_ok()
}

fn service(base_url: BrantaServerBaseUrl, privacy: PrivacyMode) -> BrantaService {
    BrantaService::new(BrantaClientOptions {
        base_url,
        default_api_key: None,
        hmac_secret: None,
        privacy,
    })
}

const NOT_FOUND: &str = "bitcoin:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

const ZK_ON_CHAIN: &str = "bitcoin:bc1q6745z6cy3u0k9nprurh3x804c4r7u3u8vxca2n\
?branta_id=z15b5EsbP5LHJrFco38%2BFp%2BHVaiopAY676NCKek8e1Q%2B4a370TyYhvloS8uLCUHfJ4CzeI%2FbOFmFDGp\
AQszB0gu1pJ1HOQ%3D%3D&branta_secret=c6e9eb30-6258-4432-9847-bdcc4fd4b0db";

mod production_loose {
    use super::*;

    const ON_CHAIN: &str = "bitcoin:bc1qu3k6geqdjncaarsu2vq56tt8php5vsug9kasmq";
    const LIGHTNING: &str = "lightning:lnbc17760n1p4r4tqupp5yuapqmxldkc8smuwa6t8shkdg9gezulu0vc7htepfsvweph8kqfsdphgfexzmn5vysyge\
tkv4kx7ur9wgsyc6t8dp6xu6twvusy27rpd4cxcegcqzzsxq97zvuqsp53564rg6w4xjqy7jamcfqxyy83a0j8nzfs0wpevs3\
7t5ln49q6hrs9qxpqysgq47hpqmv34g25le8sceq9jdvul2nz7ucyu0vucv56nlfe40x7n3jsu8duxjrn6tgvdspt872crk9ze\
atafznm9c57m039z7wyx6g3njsqkchkdh";
    const ZK_LIGHTNING: &str = "lightning:lnbc17760n1p4r4flypp5k56kq3v2935rl3glkqu9vngfueud2zj87hjcff3t0kn0yrge0pfqdzjgfexzmn5vysz6gz\
yv4mx2mr0wpjhygzvd9nksarwd9hxwgz6v4ex7gztdehhwmr9v3nk2gz90psk6urvv5cqzzsxq97zvuqsp5hut3t0l0s5mvp9yr\
06v4253kqtf452z6c65s6g9sga445hc03v6s9qxpqysgqqm430zkk9uymjgvllr3aha88hc6q59etxasfqswn8r8pfm3dstlpp46\
azv906xtcj3wzprxup5fxn65a5wymt7zzq9sw9qdzx8rgdhcpk80nrg";

    fn svc() -> BrantaService {
        service(BrantaServerBaseUrl::Production, PrivacyMode::Loose)
    }

    #[tokio::test]
    async fn on_chain_returns_payment() {
        if skip_integration() {
            return;
        }
        let result = svc().get_payments_by_qr_code(ON_CHAIN, None).await.unwrap();
        assert!(!result.payments.is_empty());
    }

    #[tokio::test]
    async fn lightning_returns_payment() {
        if skip_integration() {
            return;
        }
        let result = svc()
            .get_payments_by_qr_code(LIGHTNING, None)
            .await
            .unwrap();
        assert!(!result.payments.is_empty());
    }

    #[tokio::test]
    async fn zk_on_chain_returns_payment() {
        if skip_integration() {
            return;
        }
        let result = svc()
            .get_payments_by_qr_code(ZK_ON_CHAIN, None)
            .await
            .unwrap();
        assert!(!result.payments.is_empty());
    }

    #[tokio::test]
    async fn zk_lightning_returns_payment() {
        if skip_integration() {
            return;
        }
        let result = svc()
            .get_payments_by_qr_code(ZK_LIGHTNING, None)
            .await
            .unwrap();
        assert!(!result.payments.is_empty());
    }

    #[tokio::test]
    async fn not_found_returns_empty() {
        if skip_integration() {
            return;
        }
        let result = svc()
            .get_payments_by_qr_code(NOT_FOUND, None)
            .await
            .unwrap();
        assert!(result.payments.is_empty());
    }
}

mod production_strict {
    use super::*;

    const ON_CHAIN: &str = "bitcoin:bc1qu3k6geqdjncaarsu2vq56tt8php5vsug9kasmq";
    const LIGHTNING: &str = "lightning:lnbc17760n1p4r4tqupp5yuapqmxldkc8smuwa6t8shkdg9gezulu0vc7htepfsvweph8kqfsdphgfexzmn5vysyge\
tkv4kx7ur9wgsyc6t8dp6xu6twvusy27rpd4cxcegcqzzsxq97zvuqsp53564rg6w4xjqy7jamcfqxyy83a0j8nzfs0wpevs3\
7t5ln49q6hrs9qxpqysgq47hpqmv34g25le8sceq9jdvul2nz7ucyu0vucv56nlfe40x7n3jsu8duxjrn6tgvdspt872crk9ze\
atafznm9c57m039z7wyx6g3njsqkchkdh";
    const ZK_LIGHTNING: &str = "lightning:lnbc17760n1p4r4flypp5k56kq3v2935rl3glkqu9vngfueud2zj87hjcff3t0kn0yrge0pfqdzjgfexzmn5vysz6gz\
yv4mx2mr0wpjhygzvd9nksarwd9hxwgz6v4ex7gztdehhwmr9v3nk2gz90psk6urvv5cqzzsxq97zvuqsp5hut3t0l0s5mvp9yr\
06v4253kqtf452z6c65s6g9sga445hc03v6s9qxpqysgqqm430zkk9uymjgvllr3aha88hc6q59etxasfqswn8r8pfm3dstlpp46\
azv906xtcj3wzprxup5fxn65a5wymt7zzq9sw9qdzx8rgdhcpk80nrg";

    fn svc() -> BrantaService {
        service(BrantaServerBaseUrl::Production, PrivacyMode::Strict)
    }

    #[tokio::test]
    async fn on_chain_plain_text_returns_empty() {
        if skip_integration() {
            return;
        }
        let result = svc().get_payments_by_qr_code(ON_CHAIN, None).await.unwrap();
        assert!(result.payments.is_empty());
    }

    #[tokio::test]
    async fn lightning_plain_text_returns_empty() {
        if skip_integration() {
            return;
        }
        let result = svc()
            .get_payments_by_qr_code(LIGHTNING, None)
            .await
            .unwrap();
        assert!(result.payments.is_empty());
    }

    #[tokio::test]
    async fn zk_on_chain_returns_payment() {
        if skip_integration() {
            return;
        }
        let result = svc()
            .get_payments_by_qr_code(ZK_ON_CHAIN, None)
            .await
            .unwrap();
        assert!(!result.payments.is_empty());
    }

    #[tokio::test]
    async fn zk_lightning_returns_payment() {
        if skip_integration() {
            return;
        }
        let result = svc()
            .get_payments_by_qr_code(ZK_LIGHTNING, None)
            .await
            .unwrap();
        assert!(!result.payments.is_empty());
    }

    #[tokio::test]
    async fn not_found_plain_text_returns_empty() {
        if skip_integration() {
            return;
        }
        let result = svc()
            .get_payments_by_qr_code(NOT_FOUND, None)
            .await
            .unwrap();
        assert!(result.payments.is_empty());
    }
}

mod staging_loose {
    use super::*;

    const ON_CHAIN: &str = "bitcoin:bc1qgw3dzmhnyvcswc9r0v0z0ajtp8ulm4nuyeahwr";
    const LIGHTNING: &str = "lightning:lnbc25830n1p4quq9ppp5zszvpgxtu6uwyur6sf7rayc0meqprqlkv30xjzclh6nzm7gavd8sdzh2d6xzemfdenjqsnjv\
9h8gcfq95sygetkv4kx7ur9wgsyc6t8dp6xu6twvusy27rpd4cxcefq9pfhgct8d9hxw2gcqzzsxqzursp5fcfx5st7x8rgxra42\
j47hskmzkcz96mx84xcnvs9lpsmjyzqhw2q9qxpqysgq06lxdc93jjpuqsal9unlfct6wuv0v53yxa8kksl85g3qdw7qks7z9jkq3\
9c6wgzar72luwd38sfj0klyqv0zgns4rq7nafnd8qeuudcqql7at4";
    const ZK_LIGHTNING: &str = "lightning:lnbc25840n1p4qml83pp5aztzddx4k87m0wkd6wmgxr9753400mcj7sa89sa392krmueqv9qqdz92d6xzemfdenjqsnjv\
9h8gcfq95s9xarpva5kueeqtf9jqsn0d36zqvf3ypzhsctdwpkx2cqzzsxqzursp5c6dt82gqpn5vucmqtctur0p3cuur6xqgc63\
48wtz7adtgug9uf2q9qxpqysgq5yt6x946w3664th4h02pug9yhgszpznqyfwzndjk2sxe0878slqkdhgce4mr5ky2ux4gy4yt0vs\
y536tencls8fvu5wdzyaq548yf4qqu0lyg7";

    fn svc() -> BrantaService {
        service(BrantaServerBaseUrl::Staging, PrivacyMode::Loose)
    }

    #[tokio::test]
    async fn on_chain_returns_payment() {
        if skip_integration() {
            return;
        }
        let result = svc().get_payments_by_qr_code(ON_CHAIN, None).await.unwrap();
        assert!(!result.payments.is_empty());
    }

    #[tokio::test]
    async fn lightning_returns_payment() {
        if skip_integration() {
            return;
        }
        let result = svc()
            .get_payments_by_qr_code(LIGHTNING, None)
            .await
            .unwrap();
        assert!(!result.payments.is_empty());
    }

    #[tokio::test]
    async fn zk_on_chain_returns_payment() {
        if skip_integration() {
            return;
        }
        let result = svc()
            .get_payments_by_qr_code(ZK_ON_CHAIN, None)
            .await
            .unwrap();
        assert!(!result.payments.is_empty());
    }

    #[tokio::test]
    async fn zk_lightning_returns_payment() {
        if skip_integration() {
            return;
        }
        let result = svc()
            .get_payments_by_qr_code(ZK_LIGHTNING, None)
            .await
            .unwrap();
        assert!(!result.payments.is_empty());
    }

    #[tokio::test]
    async fn not_found_returns_empty() {
        if skip_integration() {
            return;
        }
        let result = svc()
            .get_payments_by_qr_code(NOT_FOUND, None)
            .await
            .unwrap();
        assert!(result.payments.is_empty());
    }
}

mod staging_strict {
    use super::*;

    const ON_CHAIN: &str = "bitcoin:bc1qgw3dzmhnyvcswc9r0v0z0ajtp8ulm4nuyeahwr";
    const ZK_LIGHTNING: &str = "lightning:lnbc25840n1p4qml83pp5aztzddx4k87m0wkd6wmgxr9753400mcj7sa89sa392krmueqv9qqdz92d6xzemfdenjqsnjv\
9h8gcfq95s9xarpva5kueeqtf9jqsn0d36zqvf3ypzhsctdwpkx2cqzzsxqzursp5c6dt82gqpn5vucmqtctur0p3cuur6xqgc63\
48wtz7adtgug9uf2q9qxpqysgq5yt6x946w3664th4h02pug9yhgszpznqyfwzndjk2sxe0878slqkdhgce4mr5ky2ux4gy4yt0vs\
y536tencls8fvu5wdzyaq548yf4qqu0lyg7";

    fn svc() -> BrantaService {
        service(BrantaServerBaseUrl::Staging, PrivacyMode::Strict)
    }

    #[tokio::test]
    async fn on_chain_plain_text_returns_empty() {
        if skip_integration() {
            return;
        }
        let result = svc().get_payments_by_qr_code(ON_CHAIN, None).await.unwrap();
        assert!(result.payments.is_empty());
    }

    #[tokio::test]
    async fn zk_on_chain_returns_payment() {
        if skip_integration() {
            return;
        }
        let result = svc()
            .get_payments_by_qr_code(ZK_ON_CHAIN, None)
            .await
            .unwrap();
        assert!(!result.payments.is_empty());
    }

    #[tokio::test]
    async fn zk_lightning_returns_payment() {
        if skip_integration() {
            return;
        }
        let result = svc()
            .get_payments_by_qr_code(ZK_LIGHTNING, None)
            .await
            .unwrap();
        assert!(!result.payments.is_empty());
    }

    #[tokio::test]
    async fn not_found_plain_text_returns_empty() {
        if skip_integration() {
            return;
        }
        let result = svc()
            .get_payments_by_qr_code(NOT_FOUND, None)
            .await
            .unwrap();
        assert!(result.payments.is_empty());
    }
}
