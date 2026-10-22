//! Key rotation for response cache encryption, across a mixed fleet.
//!
//! Each test runs several router processes at the same time against ONE Redis namespace, each with
//! its own configuration, the way routers do while a new key is being rolled out. The subgraph
//! answers with a cacheable `Cache-Control: public` response, so no `private_id` is involved and
//! a router that starts later reads what another one wrote.

use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use base64::Engine as _;
use base64::prelude::BASE64_STANDARD;
use fred::clients::Client;
use fred::interfaces::ClientLike;
use fred::interfaces::KeysInterface;
use fred::types::Builder;
use fred::types::scan::ScanType;
use fred::types::scan::Scanner;
use futures::StreamExt as _;
use serde_json::Value;
use serde_json::json;
use wiremock::ResponseTemplate;

use crate::integration::IntegrationTest;
use crate::integration::common::Query;
use crate::integration::common::namespace;

const REDIS_URL: &str = "redis://127.0.0.1:6379";
const SUBGRAPH: &str = "products";

const QUERY_NAMES: &str = "{ topProducts { name } }";
const QUERY_UPCS: &str = "{ topProducts { upc } }";
const QUERY_BOTH: &str = "{ topProducts { name upc } }";

/// What the subgraph returns for every query: the router only keeps the fields a query asks for.
fn subgraph_response() -> ResponseTemplate {
    ResponseTemplate::new(200)
        .insert_header("cache-control", "public, max-age=300")
        .set_body_json(json!({
            "data": { "topProducts": [
                { "name": "Table", "upc": "1" },
                { "name": "Couch", "upc": "2" },
            ] }
        }))
}

fn expected(query: &str) -> Value {
    let products = match query {
        QUERY_NAMES => json!([{ "name": "Table" }, { "name": "Couch" }]),
        QUERY_UPCS => json!([{ "upc": "1" }, { "upc": "2" }]),
        _ => json!([{ "name": "Table", "upc": "1" }, { "name": "Couch", "upc": "2" }]),
    };
    json!({ "data": { "topProducts": products } })
}

/// A 32-byte key, as the `secret` of a key in the configuration.
fn key(id: &str, byte: u8) -> Value {
    json!({ "id": id, "secret": BASE64_STANDARD.encode([byte; 32]) })
}

fn encryption(active: Value, previous_keys: Vec<Value>) -> Value {
    json!({ "key": active, "previous_keys": previous_keys })
}

/// One router of the fleet, and how many requests reached its subgraph.
struct Member {
    router: IntegrationTest,
    subgraph_requests: Arc<AtomicUsize>,
}

impl Member {
    async fn start(namespace: &str, encryption: Value) -> Self {
        let config = json!({
            "include_subgraph_errors": { "all": true },
            "telemetry": { "exporters": { "metrics": { "prometheus": {
                "enabled": true,
                "path": "/metrics",
            } } } },
            "response_cache": {
                "enabled": true,
                "subgraph": { "all": {
                    "redis": {
                        "urls": [REDIS_URL],
                        "pool_size": 1,
                        "required_to_start": true,
                    },
                    "ttl": "10m",
                    "encryption": encryption,
                } },
            },
        });
        let subgraph_requests = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&subgraph_requests);
        let mut router = IntegrationTest::builder()
            .config(serde_yaml::to_string(&config).unwrap())
            .responder(subgraph_response())
            .subgraph_callback(Box::new(move || {
                counter.fetch_add(1, Ordering::Relaxed);
            }))
            .redis_namespace(namespace.to_string())
            .build()
            .await;
        router.start().await;
        router.assert_started().await;
        Self {
            router,
            subgraph_requests,
        }
    }

    /// Runs `query`, checks that the client got the right data, and returns how many requests
    /// that took to the subgraph (0 for a cache hit).
    async fn query(&mut self, query: &str) -> usize {
        let before = self.subgraph_requests.load(Ordering::Relaxed);
        let (_trace_id, response) = self
            .router
            .execute_query(Query::builder().body(json!({ "query": query })).build())
            .await;
        assert_eq!(response.status(), 200);
        assert_eq!(response.json::<Value>().await.unwrap(), expected(query));
        self.subgraph_requests.load(Ordering::Relaxed) - before
    }

    /// Waits for the router's encryption counter to show `count` values for this combination.
    async fn assert_encryption_counter(
        &self,
        key_id: &str,
        operation: &str,
        outcome: &str,
        count: usize,
    ) {
        self.router
            .assert_metrics_contains_multiple(
                vec![&format!(
                    r#"key_id="{key_id}",operation="{operation}",outcome="{outcome}",subgraph_name="{SUBGRAPH}"<anyopt>}} {count}"#
                )],
                None,
            )
            .await;
    }

    async fn assert_no_unknown_key(&self) {
        let metrics = self
            .router
            .get_metrics_response()
            .await
            .expect("failed to fetch metrics")
            .text()
            .await
            .unwrap();
        assert!(
            !metrics.contains(r#"outcome="unknown_key""#),
            "unexpected unknown_key outcome:\n{metrics}"
        );
    }
}

async fn redis_client() -> Client {
    let client = Builder::from_config(fred::prelude::Config::from_url(REDIS_URL).unwrap())
        .build()
        .unwrap();
    client.init().await.unwrap();
    client
}

/// Waits until at least `count` cached values in `namespace` are sealed with the key `key_id`.
///
/// Cache writes happen after the response is returned, so a test that wants to read what a
/// request wrote has to wait for it to land.
async fn wait_for_sealed(namespace: &str, key_id: &str, count: usize) {
    let client = redis_client().await;
    let marker = format!(r#""kid":"{key_id}""#);
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let mut sealed = 0;
        let mut keys = client.scan(format!("{namespace}:*"), Some(100), Some(ScanType::String));
        while let Some(page) = keys.next().await {
            for key in page.unwrap().take_results().unwrap_or_default() {
                let value: Option<String> = client.get(key).await.unwrap();
                sealed += usize::from(value.is_some_and(|value| value.contains(&marker)));
            }
        }
        if sealed >= count {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {count} cached value(s) sealed with {key_id} in {namespace}; found {sealed}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// Two-phase rotation: the new key goes to `previous_keys` everywhere first, then becomes the
/// active key. Whatever either router writes is a hit on both, with no extra misses.
#[tokio::test(flavor = "multi_thread")]
async fn two_phase_rotation_has_no_misses_and_no_unknown_key() {
    let namespace = namespace();
    let (k1, k2) = (key("k1", 1), key("k2", 2));

    // Phase 1: A has K1 active; B has K1 active and K2 as a previous key.
    {
        let mut a = Member::start(&namespace, encryption(k1.clone(), vec![])).await;
        let mut b = Member::start(&namespace, encryption(k1.clone(), vec![k2.clone()])).await;

        assert_eq!(a.query(QUERY_NAMES).await, 1, "first request is a miss");
        wait_for_sealed(&namespace, "k1", 1).await;
        assert_eq!(b.query(QUERY_NAMES).await, 0, "B reads what A wrote");
        b.assert_encryption_counter("k1", "decrypt", "success", 1)
            .await;

        assert_eq!(b.query(QUERY_UPCS).await, 1, "a new query is a miss");
        wait_for_sealed(&namespace, "k1", 2).await;
        assert_eq!(a.query(QUERY_UPCS).await, 0, "A reads what B wrote");
        a.assert_encryption_counter("k1", "decrypt", "success", 1)
            .await;

        a.assert_no_unknown_key().await;
        b.assert_no_unknown_key().await;
    }

    // Phase 2: B makes K2 active with K1 previous; A gets K2 as a previous key.
    let mut a = Member::start(&namespace, encryption(k1.clone(), vec![k2.clone()])).await;
    let mut b = Member::start(&namespace, encryption(k2.clone(), vec![k1.clone()])).await;

    assert_eq!(
        b.query(QUERY_NAMES).await,
        0,
        "B reads a value sealed with K1"
    );
    b.assert_encryption_counter("k1", "decrypt", "success", 1)
        .await;

    assert_eq!(b.query(QUERY_BOTH).await, 1, "a new query is a miss");
    b.assert_encryption_counter("k2", "encrypt", "success", 1)
        .await;
    wait_for_sealed(&namespace, "k2", 1).await;
    assert_eq!(
        a.query(QUERY_BOTH).await,
        0,
        "A reads a value sealed with K2"
    );
    a.assert_encryption_counter("k2", "decrypt", "success", 1)
        .await;
    assert_eq!(
        a.query(QUERY_UPCS).await,
        0,
        "A still reads a value sealed with K1"
    );
    a.assert_encryption_counter("k1", "decrypt", "success", 1)
        .await;

    a.assert_no_unknown_key().await;
    b.assert_no_unknown_key().await;
}

/// One-step swap: B already writes with K2 while A only has K1. A treats what B wrote as a miss,
/// the client still gets the right data, and A rewrites the entry with its own key.
#[tokio::test(flavor = "multi_thread")]
async fn one_step_swap_is_a_miss_for_a_router_without_the_new_key() {
    let namespace = namespace();
    let (k1, k2) = (key("k1", 1), key("k2", 2));
    let mut b = Member::start(&namespace, encryption(k2, vec![k1.clone()])).await;
    let mut a = Member::start(&namespace, encryption(k1, vec![])).await;

    assert_eq!(b.query(QUERY_NAMES).await, 1);
    wait_for_sealed(&namespace, "k2", 1).await;

    assert_eq!(a.query(QUERY_NAMES).await, 1, "A can't read K2: a miss");
    a.assert_encryption_counter("unknown", "decrypt", "unknown_key", 1)
        .await;
    a.assert_encryption_counter("k1", "encrypt", "success", 1)
        .await;
    wait_for_sealed(&namespace, "k1", 1).await;

    assert_eq!(a.query(QUERY_NAMES).await, 0, "A reads its own rewrite");
    a.assert_encryption_counter("k1", "decrypt", "success", 1)
        .await;
}

/// Removing the old key: what is still sealed with it is a miss, never an error for the client.
#[tokio::test(flavor = "multi_thread")]
async fn values_sealed_with_a_removed_key_are_misses() {
    let namespace = namespace();
    let (k1, k2) = (key("k1", 1), key("k2", 2));
    let mut old = Member::start(&namespace, encryption(k1, vec![])).await;
    let mut new = Member::start(&namespace, encryption(k2, vec![])).await;

    assert_eq!(old.query(QUERY_NAMES).await, 1);
    wait_for_sealed(&namespace, "k1", 1).await;

    assert_eq!(new.query(QUERY_NAMES).await, 1, "K1 is gone: a miss");
    new.assert_encryption_counter("unknown", "decrypt", "unknown_key", 1)
        .await;
    wait_for_sealed(&namespace, "k2", 1).await;

    assert_eq!(
        new.query(QUERY_NAMES).await,
        0,
        "the entry was rewritten with K2"
    );
    new.assert_encryption_counter("k2", "decrypt", "success", 1)
        .await;
}
