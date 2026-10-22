//! Encryption of response cache values at rest.
//!
//! When `encryption` is configured for a subgraph or connector source, every value the response
//! cache writes to Redis for it is sealed with its key's algorithm and stored as a JSON envelope that
//! names the key and algorithm that sealed it. A read opens the envelope with the key it names, so
//! values written under a previous key stay readable while that key is listed in `previous_keys`.
//!
//! Only values are encrypted. Redis keys, and the cache-tag index entries written next to each
//! value, are stored as they are: invalidation matches on them.

use std::borrow::Cow;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fmt;
use std::sync::Arc;

use apollo_redaction::Redacted;
use aws_lc_rs::aead::AES_256_GCM;
use aws_lc_rs::aead::AES_256_GCM_SIV;
use aws_lc_rs::aead::Aad;
use aws_lc_rs::aead::CHACHA20_POLY1305;
use aws_lc_rs::aead::LessSafeKey;
use aws_lc_rs::aead::NONCE_LEN;
use aws_lc_rs::aead::Nonce;
use aws_lc_rs::aead::RandomizedNonceKey;
use aws_lc_rs::aead::UnboundKey;
use aws_lc_rs::error::Unspecified;
use aws_lc_rs::rand;
use base64::Engine as _;
use base64::prelude::BASE64_STANDARD;
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;

use crate::plugins::response_cache::cache_tag::CacheScope;
use crate::plugins::response_cache::metrics::record_encryption;

const KEY_LEN: usize = 32;
const MAX_KEY_ID_LEN: usize = 64;
const ENVELOPE_VERSION: u8 = 1;
/// Every envelope this module writes starts with these bytes, because `enc` is the first field of
/// [`Envelope`], while a plaintext `CacheValue` starts with `{"data":`. Checking the prefix tells
/// the two apart without parsing the value twice.
const ENVELOPE_PREFIX: &str = r#"{"enc":"#;

/// Encryption of the values cached for a subgraph or connector source.
#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct EncryptionConfig {
    /// The key that encrypts values written from now on. It also decrypts them.
    pub(crate) key: KeyConfig,
    /// Keys that only decrypt. When rotating, list the previous `key` here so the values it
    /// encrypted stay readable until they expire.
    #[serde(default)]
    pub(crate) previous_keys: Vec<KeyConfig>,
}

/// The algorithm a key encrypts with. Every algorithm takes a 32-byte key.
#[derive(Clone, Copy, Debug, Default, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
pub(crate) enum Algorithm {
    /// AES-256-GCM
    #[default]
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
    /// AES-256-GCM-SIV: stays secure if a nonce is ever reused.
    #[serde(rename = "aes-256-gcm-siv")]
    Aes256GcmSiv,
    /// ChaCha20-Poly1305: fast without AES hardware acceleration.
    #[serde(rename = "chacha20-poly1305")]
    Chacha20Poly1305,
}

impl Algorithm {
    /// The name this algorithm has in the configuration, the stored envelope and metrics.
    fn as_str(self) -> &'static str {
        match self {
            Algorithm::Aes256Gcm => "aes-256-gcm",
            Algorithm::Aes256GcmSiv => "aes-256-gcm-siv",
            Algorithm::Chacha20Poly1305 => "chacha20-poly1305",
        }
    }
}

/// An encryption key, and the identifier stored with each value it encrypts.
#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct KeyConfig {
    /// Identifier stored with each value this key encrypts, so the router knows which key
    /// decrypts it. At most 64 characters.
    pub(crate) id: String,
    /// The algorithm this key encrypts with. To change algorithm, rotate to a new key.
    #[serde(default)]
    pub(crate) algorithm: Algorithm,
    /// The key itself: 32 bytes, base64-encoded.
    #[serde(deserialize_with = "crate::plugin::serde::deserialize_redacted_string")]
    pub(crate) secret: Redacted<String>,
}

/// The `encryption` settings of one scope: its `all` block, and the names that set their own.
pub(crate) struct ScopeEncryptionConfig<'a> {
    pub(crate) all: Option<&'a EncryptionConfig>,
    /// Names whose own setting replaces `all`. `None` turns encryption off for that name.
    pub(crate) overrides: Vec<(&'a str, Option<&'a EncryptionConfig>)>,
}

/// A problem with the configured keys. Messages name the key ID, never the secret.
#[derive(Debug, PartialEq, thiserror::Error)]
pub(crate) enum ConfigError {
    #[error("response cache encryption key IDs must not be empty")]
    EmptyKeyId,
    #[error("response cache encryption key ID `{0}` is longer than 64 characters")]
    KeyIdTooLong(String),
    #[error("response cache encryption key `{0}` is not valid base64")]
    InvalidBase64(String),
    #[error("response cache encryption key `{id}` must be 32 bytes, but it is {len} bytes")]
    InvalidLength { id: String, len: usize },
    #[error("response cache encryption key `{id}` can't be used with {algorithm}")]
    InvalidKey { id: String, algorithm: &'static str },
    #[error(
        "response cache encryption key ID `{0}` is configured with two different secrets or algorithms"
    )]
    ConflictingKeyId(String),
}

/// Why a cached value was not used. Each one makes the lookup a cache miss.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum EncryptionError {
    #[error("the cached value was encrypted with a key that is not configured")]
    UnknownKey,
    #[error("the cached value could not be decrypted")]
    Decrypt,
    #[error("the cached value is not encrypted, but encryption is configured for it")]
    Plaintext,
    #[error("the cached value is not a valid cache entry")]
    Malformed,
    #[error("the value could not be encrypted")]
    Encrypt,
}

impl EncryptionError {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            EncryptionError::UnknownKey => "Encryption::UnknownKey",
            EncryptionError::Decrypt => "Encryption::Decrypt",
            EncryptionError::Plaintext => "Encryption::Plaintext",
            EncryptionError::Malformed => "Encryption::Malformed",
            EncryptionError::Encrypt => "Encryption::Encrypt",
        }
    }

    /// The `outcome` attribute of the encryption metric.
    fn outcome(&self) -> &'static str {
        match self {
            EncryptionError::UnknownKey => "unknown_key",
            EncryptionError::Decrypt => "decrypt_failed",
            EncryptionError::Plaintext => "plaintext_rejected",
            EncryptionError::Malformed => "malformed",
            EncryptionError::Encrypt => "encrypt_failed",
        }
    }
}

fn outcome<T>(result: &Result<T, EncryptionError>) -> &'static str {
    result
        .as_ref()
        .map_or_else(EncryptionError::outcome, |_| "success")
}

/// Every key configured across the response cache, and which one encrypts each name's values.
///
/// Built once per plugin instance and shared by every Redis storage, because subgraphs on the
/// same Redis configuration share one storage while each can use its own key.
pub(crate) struct CacheEncryption {
    /// Every configured key, active or previous, by ID.
    keys: HashMap<String, Key>,
    subgraph: ActiveKeys,
    connector: ActiveKeys,
}

impl fmt::Debug for CacheEncryption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CacheEncryption")
            .field("key_ids", &self.keys.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl CacheEncryption {
    /// Builds the keyring, or returns `None` when no subgraph or connector source configures
    /// encryption.
    pub(crate) fn new(
        subgraph: ScopeEncryptionConfig<'_>,
        connector: ScopeEncryptionConfig<'_>,
    ) -> Result<Option<Self>, ConfigError> {
        let mut secrets = HashMap::new();
        let subgraph = ActiveKeys::register(subgraph, &mut secrets)?;
        let connector = ActiveKeys::register(connector, &mut secrets)?;
        if secrets.is_empty() {
            return Ok(None);
        }

        let keys = secrets
            .into_iter()
            .map(|(id, (algorithm, bytes))| {
                Cipher::new(algorithm, &bytes)
                    .map(|cipher| (id.clone(), Key { algorithm, cipher }))
                    .map_err(|_| ConfigError::InvalidKey {
                        id,
                        algorithm: algorithm.as_str(),
                    })
            })
            .collect::<Result<_, _>>()?;

        Ok(Some(Self {
            keys,
            subgraph,
            connector,
        }))
    }

    /// This keyring as a storage serving `scope` uses it, or `None` when no name in that scope
    /// has encryption, so its storage keeps reading values without any decoding of its own.
    pub(crate) fn for_scope(self: &Arc<Self>, scope: CacheScope) -> Option<ScopedEncryption> {
        let scoped = ScopedEncryption {
            keyring: self.clone(),
            scope,
        };
        let active = scoped.active_keys();
        (active.all.is_some() || active.overrides.values().any(Option::is_some)).then_some(scoped)
    }
}

/// A configured key and the algorithm it was configured with.
struct Key {
    algorithm: Algorithm,
    cipher: Cipher,
}

impl Key {
    /// Encrypts `value`, the serialized cache value stored under `cache_key`, into an envelope
    /// naming this key, which is stored under `key_id`.
    fn seal(
        &self,
        key_id: &str,
        cache_key: &str,
        value: String,
    ) -> Result<String, EncryptionError> {
        let mut in_out = value.into_bytes();
        // The cache key is authenticated with the value, so a value copied to another key in
        // Redis fails to decrypt instead of answering for the wrong data.
        let nonce = self
            .cipher
            .seal(cache_key.as_bytes(), &mut in_out)
            .map_err(|_| EncryptionError::Encrypt)?;

        serde_json::to_string(&Envelope {
            enc: ENVELOPE_VERSION,
            kid: Cow::Borrowed(key_id),
            alg: self.algorithm,
            nonce: BASE64_STANDARD.encode(nonce),
            ct: BASE64_STANDARD.encode(&in_out),
        })
        .map_err(|_| EncryptionError::Encrypt)
    }
}

/// A key ready to seal and open values.
///
/// The AES algorithms let aws-lc-rs generate the nonce. It doesn't support ChaCha20-Poly1305
/// that way, so that one gets a random nonce from here.
enum Cipher {
    Randomized(RandomizedNonceKey),
    ChaCha(LessSafeKey),
}

impl Cipher {
    fn new(algorithm: Algorithm, key: &[u8]) -> Result<Self, Unspecified> {
        match algorithm {
            Algorithm::Aes256Gcm => {
                RandomizedNonceKey::new(&AES_256_GCM, key).map(Self::Randomized)
            }
            Algorithm::Aes256GcmSiv => {
                RandomizedNonceKey::new(&AES_256_GCM_SIV, key).map(Self::Randomized)
            }
            Algorithm::Chacha20Poly1305 => UnboundKey::new(&CHACHA20_POLY1305, key)
                .map(|key| Self::ChaCha(LessSafeKey::new(key))),
        }
    }

    /// Encrypts `in_out` in place, appends the tag, and returns the nonce it used.
    fn seal(&self, aad: &[u8], in_out: &mut Vec<u8>) -> Result<[u8; NONCE_LEN], Unspecified> {
        match self {
            Self::Randomized(key) => {
                let nonce = key.seal_in_place_append_tag(Aad::from(aad), in_out)?;
                Ok(*nonce.as_ref())
            }
            Self::ChaCha(key) => {
                let mut nonce = [0; NONCE_LEN];
                rand::fill(&mut nonce)?;
                key.seal_in_place_append_tag(
                    Nonce::assume_unique_for_key(nonce),
                    Aad::from(aad),
                    in_out,
                )?;
                Ok(nonce)
            }
        }
    }

    /// Decrypts `in_out` in place and returns the length of the plaintext at its start.
    fn open(&self, nonce: Nonce, aad: &[u8], in_out: &mut [u8]) -> Result<usize, Unspecified> {
        match self {
            Self::Randomized(key) => key.open_in_place(nonce, Aad::from(aad), in_out),
            Self::ChaCha(key) => key.open_in_place(nonce, Aad::from(aad), in_out),
        }
        .map(|plaintext| plaintext.len())
    }
}

/// The ID of the key that encrypts each name's values, for one scope.
#[derive(Default)]
struct ActiveKeys {
    all: Option<String>,
    overrides: HashMap<String, Option<String>>,
}

impl ActiveKeys {
    /// Decodes and checks every key `config` lists, adding them to `secrets`, and records which
    /// key encrypts each name.
    fn register(
        config: ScopeEncryptionConfig<'_>,
        secrets: &mut HashMap<String, (Algorithm, Vec<u8>)>,
    ) -> Result<Self, ConfigError> {
        let all = config
            .all
            .map(|encryption| register_keys(encryption, secrets))
            .transpose()?;
        let overrides = config
            .overrides
            .into_iter()
            .map(|(name, encryption)| {
                let active = encryption
                    .map(|encryption| register_keys(encryption, secrets))
                    .transpose()?;
                Ok((name.to_string(), active))
            })
            .collect::<Result<_, ConfigError>>()?;
        Ok(Self { all, overrides })
    }

    fn get(&self, name: &str) -> Option<&str> {
        match self.overrides.get(name) {
            Some(active) => active.as_deref(),
            None => self.all.as_deref(),
        }
    }
}

/// Adds `encryption`'s keys to `secrets` and returns the ID of its active key.
fn register_keys(
    encryption: &EncryptionConfig,
    secrets: &mut HashMap<String, (Algorithm, Vec<u8>)>,
) -> Result<String, ConfigError> {
    for key in std::iter::once(&encryption.key).chain(&encryption.previous_keys) {
        let configured = (key.algorithm, decode_secret(key)?);
        // The `all` block is copied into every subgraph that sets other options, so the same key
        // is routinely listed more than once. Only a different secret or algorithm under one ID
        // is an error.
        match secrets.entry(key.id.clone()) {
            Entry::Occupied(existing) if *existing.get() != configured => {
                return Err(ConfigError::ConflictingKeyId(key.id.clone()));
            }
            Entry::Occupied(_) => {}
            Entry::Vacant(entry) => {
                entry.insert(configured);
            }
        }
    }
    Ok(encryption.key.id.clone())
}

fn decode_secret(key: &KeyConfig) -> Result<Vec<u8>, ConfigError> {
    if key.id.is_empty() {
        return Err(ConfigError::EmptyKeyId);
    }
    if key.id.chars().count() > MAX_KEY_ID_LEN {
        return Err(ConfigError::KeyIdTooLong(key.id.clone()));
    }
    let bytes = BASE64_STANDARD
        .decode(key.secret.unredact())
        .map_err(|_| ConfigError::InvalidBase64(key.id.clone()))?;
    if bytes.len() != KEY_LEN {
        return Err(ConfigError::InvalidLength {
            id: key.id.clone(),
            len: bytes.len(),
        });
    }
    Ok(bytes)
}

/// A [`CacheEncryption`] as one storage uses it. A storage serves either subgraphs or connector
/// sources, never both, so it knows which scope's names it is given.
#[derive(Clone, Debug)]
pub(crate) struct ScopedEncryption {
    keyring: Arc<CacheEncryption>,
    scope: CacheScope,
}

impl ScopedEncryption {
    fn active_keys(&self) -> &ActiveKeys {
        match self.scope {
            CacheScope::Subgraph => &self.keyring.subgraph,
            CacheScope::Connector => &self.keyring.connector,
        }
    }

    /// Encrypts `value`, the serialized cache value stored under `cache_key`, with `name`'s
    /// active key. Returns `value` unchanged when `name` has no encryption configured.
    pub(crate) fn seal(
        &self,
        name: &str,
        cache_key: &str,
        value: String,
    ) -> Result<String, EncryptionError> {
        let Some(key_id) = self.active_keys().get(name) else {
            return Ok(value);
        };
        let key = self.keyring.keys.get(key_id);
        let result = key
            .ok_or(EncryptionError::UnknownKey)
            .and_then(|key| key.seal(key_id, cache_key, value));
        record_encryption(
            "encrypt",
            key_id,
            key.map_or("unknown", |key| key.algorithm.as_str()),
            name,
            outcome(&result),
        );
        result
    }

    /// Returns the serialized cache value stored as `raw` under `cache_key`: decrypted when `raw`
    /// is an envelope, or `raw` itself when it is a plaintext value and `name` has no encryption
    /// configured.
    pub(crate) fn open<'a>(
        &self,
        name: &str,
        cache_key: &str,
        raw: &'a str,
    ) -> Result<Cow<'a, str>, EncryptionError> {
        let mut key_used = None;
        let result = self.open_value(name, cache_key, raw, &mut key_used);
        // A plaintext value served as it is was not decrypted, so it isn't counted.
        if raw.starts_with(ENVELOPE_PREFIX) || result == Err(EncryptionError::Plaintext) {
            // The key ID of a stored envelope is data from Redis, so it only labels the metric
            // once it is known to be a configured key.
            let (key_id, algorithm) = key_used.map_or(("unknown", "unknown"), |(id, algorithm)| {
                (id.as_str(), algorithm.as_str())
            });
            record_encryption("decrypt", key_id, algorithm, name, outcome(&result));
        }
        result
    }

    /// [`Self::open`], which also reports the configured key it resolved, if any, in `key_used`.
    fn open_value<'s, 'a>(
        &'s self,
        name: &str,
        cache_key: &str,
        raw: &'a str,
        key_used: &mut Option<(&'s String, Algorithm)>,
    ) -> Result<Cow<'a, str>, EncryptionError> {
        if !raw.starts_with(ENVELOPE_PREFIX) {
            // A plaintext value where encryption is configured was either written before it was
            // turned on, or put there by something other than the router. Neither is served.
            return match self.active_keys().get(name) {
                Some(key_id) => {
                    *key_used = self
                        .keyring
                        .keys
                        .get_key_value(key_id)
                        .map(|(id, key)| (id, key.algorithm));
                    Err(EncryptionError::Plaintext)
                }
                None => Ok(Cow::Borrowed(raw)),
            };
        }

        let envelope: Envelope<'_> =
            serde_json::from_str(raw).map_err(|_| EncryptionError::Malformed)?;
        if envelope.enc != ENVELOPE_VERSION {
            return Err(EncryptionError::Malformed);
        }
        let (key_id, key) = self
            .keyring
            .keys
            .get_key_value(envelope.kid.as_ref())
            .ok_or(EncryptionError::UnknownKey)?;
        *key_used = Some((key_id, key.algorithm));
        // A key only ever encrypts with the algorithm it is configured with.
        if envelope.alg != key.algorithm {
            return Err(EncryptionError::Malformed);
        }
        let nonce = BASE64_STANDARD
            .decode(&envelope.nonce)
            .ok()
            .and_then(|nonce| Nonce::try_assume_unique_for_key(&nonce).ok())
            .ok_or(EncryptionError::Malformed)?;
        let mut in_out = BASE64_STANDARD
            .decode(&envelope.ct)
            .map_err(|_| EncryptionError::Malformed)?;

        let plaintext_len = key
            .cipher
            .open(nonce, cache_key.as_bytes(), &mut in_out)
            .map_err(|_| EncryptionError::Decrypt)?;
        in_out.truncate(plaintext_len);
        String::from_utf8(in_out)
            .map(Cow::Owned)
            .map_err(|_| EncryptionError::Malformed)
    }
}

/// An encrypted value as stored in Redis. `enc` must stay the first field: see
/// [`ENVELOPE_PREFIX`].
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Envelope<'a> {
    /// Envelope format version.
    enc: u8,
    /// ID of the key that sealed `ct`.
    #[serde(borrow)]
    kid: Cow<'a, str>,
    /// Algorithm that sealed `ct`. It must be the algorithm `kid` is configured with.
    alg: Algorithm,
    /// Base64 of the 12-byte nonce.
    nonce: String,
    /// Base64 of the ciphertext followed by the 16-byte authentication tag.
    ct: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    const CACHE_KEY: &str = "version:1.2:subgraph:accounts:type:Query:hash:abc:data:def";
    const VALUE: &str = r#"{"data":{"accountNumber":"1234567890123456"},"cache_control":{}}"#;

    fn key(id: &str, byte: u8) -> KeyConfig {
        key_with(id, byte, Algorithm::default())
    }

    fn key_with(id: &str, byte: u8, algorithm: Algorithm) -> KeyConfig {
        KeyConfig {
            id: id.to_string(),
            algorithm,
            secret: Redacted::new(BASE64_STANDARD.encode([byte; KEY_LEN])),
        }
    }

    const ALGORITHMS: [Algorithm; 3] = [
        Algorithm::Aes256Gcm,
        Algorithm::Aes256GcmSiv,
        Algorithm::Chacha20Poly1305,
    ];

    fn encryption(key: KeyConfig, previous_keys: Vec<KeyConfig>) -> EncryptionConfig {
        EncryptionConfig { key, previous_keys }
    }

    fn subgraph_keyring(
        all: Option<&EncryptionConfig>,
        overrides: Vec<(&str, Option<&EncryptionConfig>)>,
    ) -> ScopedEncryption {
        let keyring = CacheEncryption::new(
            ScopeEncryptionConfig { all, overrides },
            ScopeEncryptionConfig {
                all: None,
                overrides: Vec::new(),
            },
        )
        .unwrap()
        .unwrap();
        Arc::new(keyring)
            .for_scope(CacheScope::Subgraph)
            .expect("a subgraph key is configured")
    }

    fn sealed_key_id(sealed: &str) -> String {
        let envelope: Envelope<'_> = serde_json::from_str(sealed).unwrap();
        envelope.kid.into_owned()
    }

    #[test]
    fn open_returns_the_sealed_value() {
        let config = encryption(key("k1", 1), Vec::new());
        let keyring = subgraph_keyring(Some(&config), Vec::new());

        let sealed = keyring
            .seal("accounts", CACHE_KEY, VALUE.to_string())
            .unwrap();

        assert_eq!(keyring.open("accounts", CACHE_KEY, &sealed).unwrap(), VALUE);
    }

    #[test]
    fn sealed_value_does_not_contain_the_plaintext() {
        let config = encryption(key("k1", 1), Vec::new());
        let keyring = subgraph_keyring(Some(&config), Vec::new());

        let sealed = keyring
            .seal("accounts", CACHE_KEY, VALUE.to_string())
            .unwrap();

        assert!(sealed.starts_with(ENVELOPE_PREFIX));
        assert!(!sealed.contains("1234567890123456"));
    }

    #[test]
    fn open_rejects_a_value_moved_to_another_cache_key() {
        let config = encryption(key("k1", 1), Vec::new());
        let keyring = subgraph_keyring(Some(&config), Vec::new());
        let sealed = keyring
            .seal("accounts", CACHE_KEY, VALUE.to_string())
            .unwrap();

        let opened = keyring.open("accounts", "some:other:key", &sealed);

        assert_eq!(opened, Err(EncryptionError::Decrypt));
    }

    #[test]
    fn open_rejects_a_tampered_ciphertext() {
        let config = encryption(key("k1", 1), Vec::new());
        let keyring = subgraph_keyring(Some(&config), Vec::new());
        let sealed = keyring
            .seal("accounts", CACHE_KEY, VALUE.to_string())
            .unwrap();
        let mut envelope: Envelope<'_> = serde_json::from_str(&sealed).unwrap();
        let mut ct = BASE64_STANDARD.decode(&envelope.ct).unwrap();
        ct[0] ^= 1;
        envelope.ct = BASE64_STANDARD.encode(ct);
        let tampered = serde_json::to_string(&envelope).unwrap();

        let opened = keyring.open("accounts", CACHE_KEY, &tampered);

        assert_eq!(opened, Err(EncryptionError::Decrypt));
    }

    #[test]
    fn open_rejects_a_value_sealed_with_an_unknown_key() {
        let old = encryption(key("k1", 1), Vec::new());
        let sealed = subgraph_keyring(Some(&old), Vec::new())
            .seal("accounts", CACHE_KEY, VALUE.to_string())
            .unwrap();
        let new = encryption(key("k2", 2), Vec::new());

        let opened = subgraph_keyring(Some(&new), Vec::new()).open("accounts", CACHE_KEY, &sealed);

        assert_eq!(opened, Err(EncryptionError::UnknownKey));
    }

    #[test]
    fn open_decrypts_a_value_sealed_with_a_previous_key() {
        let old = encryption(key("k1", 1), Vec::new());
        let sealed = subgraph_keyring(Some(&old), Vec::new())
            .seal("accounts", CACHE_KEY, VALUE.to_string())
            .unwrap();
        let rotated = encryption(key("k2", 2), vec![key("k1", 1)]);

        let opened =
            subgraph_keyring(Some(&rotated), Vec::new()).open("accounts", CACHE_KEY, &sealed);

        assert_eq!(opened.unwrap(), VALUE);
    }

    #[test]
    fn open_rejects_plaintext_for_a_name_with_encryption() {
        let config = encryption(key("k1", 1), Vec::new());
        let keyring = subgraph_keyring(Some(&config), Vec::new());

        let opened = keyring.open("accounts", CACHE_KEY, VALUE);

        assert_eq!(opened, Err(EncryptionError::Plaintext));
    }

    #[test]
    fn open_returns_plaintext_for_a_name_without_encryption() {
        let config = encryption(key("k1", 1), Vec::new());
        let keyring = subgraph_keyring(Some(&config), vec![("catalog", None)]);

        let opened = keyring.open("catalog", CACHE_KEY, VALUE);

        assert_eq!(opened.unwrap(), VALUE);
    }

    #[test]
    fn open_rejects_an_envelope_with_missing_fields() {
        let config = encryption(key("k1", 1), Vec::new());
        let keyring = subgraph_keyring(Some(&config), Vec::new());

        let opened = keyring.open("accounts", CACHE_KEY, r#"{"enc":1,"kid":"k1"}"#);

        assert_eq!(opened, Err(EncryptionError::Malformed));
    }

    #[test]
    fn open_rejects_an_envelope_of_an_unknown_version() {
        let config = encryption(key("k1", 1), Vec::new());
        let keyring = subgraph_keyring(Some(&config), Vec::new());
        let sealed = keyring
            .seal("accounts", CACHE_KEY, VALUE.to_string())
            .unwrap();
        let future = sealed.replacen(r#"{"enc":1"#, r#"{"enc":2"#, 1);

        let opened = keyring.open("accounts", CACHE_KEY, &future);

        assert_eq!(opened, Err(EncryptionError::Malformed));
    }

    #[test]
    fn seal_leaves_the_value_unchanged_for_a_name_without_encryption() {
        let config = encryption(key("k1", 1), Vec::new());
        let keyring = subgraph_keyring(Some(&config), vec![("catalog", None)]);

        let sealed = keyring
            .seal("catalog", CACHE_KEY, VALUE.to_string())
            .unwrap();

        assert_eq!(sealed, VALUE);
    }

    #[test]
    fn seal_uses_the_override_key_of_a_listed_name() {
        let all = encryption(key("all", 1), Vec::new());
        let accounts = encryption(key("accounts", 2), Vec::new());
        let keyring = subgraph_keyring(Some(&all), vec![("accounts", Some(&accounts))]);

        let sealed = keyring
            .seal("accounts", CACHE_KEY, VALUE.to_string())
            .unwrap();

        assert_eq!(sealed_key_id(&sealed), "accounts");
    }

    #[test]
    fn seal_uses_the_all_key_of_an_unlisted_name() {
        let all = encryption(key("all", 1), Vec::new());
        let accounts = encryption(key("accounts", 2), Vec::new());
        let keyring = subgraph_keyring(Some(&all), vec![("accounts", Some(&accounts))]);

        let sealed = keyring
            .seal("products", CACHE_KEY, VALUE.to_string())
            .unwrap();

        assert_eq!(sealed_key_id(&sealed), "all");
    }

    #[test]
    fn scopes_resolve_active_keys_independently() {
        let subgraph_all = encryption(key("subgraphs", 1), Vec::new());
        let connector_all = encryption(key("connectors", 2), Vec::new());
        let keyring = Arc::new(
            CacheEncryption::new(
                ScopeEncryptionConfig {
                    all: Some(&subgraph_all),
                    overrides: Vec::new(),
                },
                ScopeEncryptionConfig {
                    all: Some(&connector_all),
                    overrides: Vec::new(),
                },
            )
            .unwrap()
            .unwrap(),
        );

        let sealed = keyring
            .for_scope(CacheScope::Connector)
            .expect("a connector key is configured")
            .seal("accounts.rest", CACHE_KEY, VALUE.to_string())
            .unwrap();

        assert_eq!(sealed_key_id(&sealed), "connectors");
    }

    #[test]
    fn for_scope_returns_none_for_a_scope_without_active_keys() {
        let config = encryption(key("k1", 1), Vec::new());
        let keyring = Arc::new(
            CacheEncryption::new(
                ScopeEncryptionConfig {
                    all: Some(&config),
                    overrides: Vec::new(),
                },
                ScopeEncryptionConfig {
                    all: None,
                    overrides: vec![("accounts.rest", None)],
                },
            )
            .unwrap()
            .unwrap(),
        );

        assert!(keyring.for_scope(CacheScope::Subgraph).is_some());
        assert!(keyring.for_scope(CacheScope::Connector).is_none());
    }

    #[test]
    fn new_returns_none_without_any_encryption() {
        let empty = || ScopeEncryptionConfig {
            all: None,
            overrides: vec![("catalog", None)],
        };

        let keyring = CacheEncryption::new(empty(), empty());

        assert!(keyring.unwrap().is_none());
    }

    fn new_with(config: &EncryptionConfig) -> Result<Option<CacheEncryption>, ConfigError> {
        CacheEncryption::new(
            ScopeEncryptionConfig {
                all: Some(config),
                overrides: Vec::new(),
            },
            ScopeEncryptionConfig {
                all: None,
                overrides: Vec::new(),
            },
        )
    }

    #[test]
    fn new_rejects_a_secret_that_is_not_base64() {
        let mut bad = key("k1", 1);
        bad.secret = Redacted::new("not base64!".to_string());

        let error = new_with(&encryption(bad, Vec::new())).unwrap_err();

        assert_eq!(error, ConfigError::InvalidBase64("k1".to_string()));
    }

    #[test]
    fn new_rejects_a_secret_of_the_wrong_length() {
        let mut short = key("k1", 1);
        short.secret = Redacted::new(BASE64_STANDARD.encode([1u8; 16]));

        let error = new_with(&encryption(short, Vec::new())).unwrap_err();

        assert_eq!(
            error,
            ConfigError::InvalidLength {
                id: "k1".to_string(),
                len: 16
            }
        );
    }

    #[test]
    fn new_rejects_an_empty_key_id() {
        let error = new_with(&encryption(key("", 1), Vec::new())).unwrap_err();

        assert_eq!(error, ConfigError::EmptyKeyId);
    }

    #[test]
    fn new_rejects_a_key_id_longer_than_64_characters() {
        let id = "k".repeat(65);

        let error = new_with(&encryption(key(&id, 1), Vec::new())).unwrap_err();

        assert_eq!(error, ConfigError::KeyIdTooLong(id));
    }

    #[test]
    fn new_rejects_one_key_id_with_two_secrets() {
        let all = encryption(key("k1", 1), Vec::new());
        let accounts = encryption(key("k1", 2), Vec::new());

        let error = CacheEncryption::new(
            ScopeEncryptionConfig {
                all: Some(&all),
                overrides: vec![("accounts", Some(&accounts))],
            },
            ScopeEncryptionConfig {
                all: None,
                overrides: Vec::new(),
            },
        )
        .unwrap_err();

        assert_eq!(error, ConfigError::ConflictingKeyId("k1".to_string()));
    }

    #[test]
    fn new_accepts_one_key_listed_twice() {
        let all = encryption(key("k1", 1), Vec::new());
        let accounts = encryption(key("k1", 1), Vec::new());

        let keyring = CacheEncryption::new(
            ScopeEncryptionConfig {
                all: Some(&all),
                overrides: vec![("accounts", Some(&accounts))],
            },
            ScopeEncryptionConfig {
                all: None,
                overrides: Vec::new(),
            },
        );

        assert!(keyring.unwrap().is_some());
    }

    #[test]
    fn config_debug_output_does_not_show_the_secret() {
        let config = encryption(key("k1", 1), Vec::new());
        let secret = BASE64_STANDARD.encode([1u8; KEY_LEN]);

        let debug = format!("{config:?} {:?}", new_with(&config).unwrap().unwrap());

        assert!(!debug.contains(&secret));
    }

    #[test]
    fn config_deserializes_from_yaml() {
        let yaml = format!(
            "key:\n  id: k2\n  secret: {}\nprevious_keys:\n  - id: k1\n    secret: {}\n",
            BASE64_STANDARD.encode([2u8; KEY_LEN]),
            BASE64_STANDARD.encode([1u8; KEY_LEN]),
        );

        let config: EncryptionConfig = serde_yaml::from_str(&yaml).unwrap();

        assert_eq!(
            (config.key.id.as_str(), config.previous_keys.len()),
            ("k2", 1)
        );
    }

    #[test]
    fn open_returns_the_sealed_value_for_every_algorithm() {
        for algorithm in ALGORITHMS {
            let config = encryption(key_with("k1", 1, algorithm), Vec::new());
            let keyring = subgraph_keyring(Some(&config), Vec::new());

            let sealed = keyring
                .seal("accounts", CACHE_KEY, VALUE.to_string())
                .unwrap();

            assert!(!sealed.contains("1234567890123456"), "{algorithm:?}");
            assert_eq!(
                keyring.open("accounts", CACHE_KEY, &sealed).unwrap(),
                VALUE,
                "{algorithm:?}"
            );
        }
    }

    #[test]
    fn sealed_value_names_the_algorithm_of_its_key() {
        for algorithm in ALGORITHMS {
            let config = encryption(key_with("k1", 1, algorithm), Vec::new());
            let keyring = subgraph_keyring(Some(&config), Vec::new());

            let sealed = keyring
                .seal("accounts", CACHE_KEY, VALUE.to_string())
                .unwrap();

            let envelope: Envelope<'_> = serde_json::from_str(&sealed).unwrap();
            assert_eq!(envelope.alg, algorithm);
        }
    }

    #[test]
    fn open_rejects_every_algorithm_a_value_was_moved_from() {
        for algorithm in ALGORITHMS {
            let config = encryption(key_with("k1", 1, algorithm), Vec::new());
            let keyring = subgraph_keyring(Some(&config), Vec::new());
            let sealed = keyring
                .seal("accounts", CACHE_KEY, VALUE.to_string())
                .unwrap();

            let error = keyring
                .open("accounts", "another:cache:key", &sealed)
                .unwrap_err();

            assert_eq!(error, EncryptionError::Decrypt, "{algorithm:?}");
        }
    }

    #[test]
    fn open_rejects_an_envelope_whose_algorithm_is_not_the_keys() {
        let config = encryption(key("k1", 1), Vec::new());
        let keyring = subgraph_keyring(Some(&config), Vec::new());
        let sealed = keyring
            .seal("accounts", CACHE_KEY, VALUE.to_string())
            .unwrap();
        let mut envelope: Envelope<'_> = serde_json::from_str(&sealed).unwrap();
        envelope.alg = Algorithm::Chacha20Poly1305;

        let error = keyring
            .open(
                "accounts",
                CACHE_KEY,
                &serde_json::to_string(&envelope).unwrap(),
            )
            .unwrap_err();

        assert_eq!(error, EncryptionError::Malformed);
    }

    #[test]
    fn open_decrypts_a_value_sealed_with_a_previous_key_of_another_algorithm() {
        let old = encryption(key_with("k1", 1, Algorithm::Aes256Gcm), Vec::new());
        let sealed = subgraph_keyring(Some(&old), Vec::new())
            .seal("accounts", CACHE_KEY, VALUE.to_string())
            .unwrap();
        let rotated = encryption(
            key_with("k2", 2, Algorithm::Chacha20Poly1305),
            vec![key_with("k1", 1, Algorithm::Aes256Gcm)],
        );
        let keyring = subgraph_keyring(Some(&rotated), Vec::new());

        assert_eq!(keyring.open("accounts", CACHE_KEY, &sealed).unwrap(), VALUE);
        let resealed = keyring
            .seal("accounts", CACHE_KEY, VALUE.to_string())
            .unwrap();
        let envelope: Envelope<'_> = serde_json::from_str(&resealed).unwrap();
        assert_eq!(
            (envelope.kid.as_ref(), envelope.alg),
            ("k2", Algorithm::Chacha20Poly1305)
        );
    }

    #[test]
    fn new_rejects_one_key_id_with_two_algorithms() {
        let all = encryption(key_with("k1", 1, Algorithm::Aes256Gcm), Vec::new());
        let accounts = encryption(key_with("k1", 1, Algorithm::Aes256GcmSiv), Vec::new());

        let error = CacheEncryption::new(
            ScopeEncryptionConfig {
                all: Some(&all),
                overrides: vec![("accounts", Some(&accounts))],
            },
            ScopeEncryptionConfig {
                all: None,
                overrides: Vec::new(),
            },
        )
        .err()
        .unwrap();

        assert_eq!(error, ConfigError::ConflictingKeyId("k1".to_string()));
    }

    #[test]
    fn algorithm_defaults_to_aes_256_gcm_and_rejects_unknown_names() {
        let secret = BASE64_STANDARD.encode([1u8; KEY_LEN]);
        let default: KeyConfig =
            serde_yaml::from_str(&format!("id: k1\nsecret: {secret}")).unwrap();
        let named: KeyConfig = serde_yaml::from_str(&format!(
            "id: k1\nalgorithm: chacha20-poly1305\nsecret: {secret}"
        ))
        .unwrap();
        let unknown = serde_yaml::from_str::<KeyConfig>(&format!(
            "id: k1\nalgorithm: rot13\nsecret: {secret}"
        ));

        assert_eq!(
            (default.algorithm, named.algorithm, unknown.is_err()),
            (Algorithm::Aes256Gcm, Algorithm::Chacha20Poly1305, true)
        );
    }
}
