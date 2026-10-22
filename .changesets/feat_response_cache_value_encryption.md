### Response cache can encrypt cached values at rest

The response cache can now encrypt each value it writes to Redis, for subgraphs and for Apollo Connectors. Configure an `encryption` block with a 32-byte, base64-encoded key, normally supplied through `${env.X}` or `${file.X}` so it stays out of committed configuration:

```yaml title="router.yaml"
response_cache:
  enabled: true
  subgraph:
    all:
      redis:
        urls: ["redis://..."]
      encryption:
        key:
          id: "2026-10"
          secret: "${env.RESPONSE_CACHE_KEY}"
        previous_keys: []
```

Each key has an `id`, stored with every value it encrypts, and an `algorithm`: `aes-256-gcm` (the default), `aes-256-gcm-siv` or `chacha20-poly1305`. To rotate keys, make a new key the active `key` and keep the old one under `previous_keys` until the values it encrypted have expired. Values that can't be decrypted are cache misses. A new `apollo.router.operations.response_cache.encryption` counter reports encryptions and decryptions by key, algorithm and outcome.

The whole cached value is encrypted. Redis key names and the invalidation index, which includes the values of cache tags, are not, so avoid putting sensitive identifiers in cache tags.

By [@fernando-apollo](https://github.com/fernando-apollo) in https://github.com/apollographql/router/pull/PULL_NUMBER
