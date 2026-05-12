# Merge Analysis: origin/dev into mapping-directive

## `@mapping` Directive Spec Exposure (Corrected)

### Initial (wrong) approach

`mapping_directive_spec()` was added unconditionally to `directive_specifications()`, with the reasoning that runtime gating in `extract_mapping_directive_arguments` (which checks `connect_spec < ConnectSpec::V0_5`) was the sole control point.

### Why that was wrong

The directive spec presence itself has observable effects. When a spec is in the `directive_specifications()` list, the schema expansion step injects the directive definition into the output. A `connect/v0.4` schema that imports `@mapping` would successfully expand and include:

```graphql
directive @mapping(selection: connect__JSONSelection, as: String) repeatable on OBJECT | INTERFACE
```

This was confirmed by running `apollo-federation-cli subgraph` against a v0.4 schema that imported `@mapping` -- it exited 0 and output the directive definition.

### Corrected approach

Split-function design (plan option 1):
- `directive_specifications()` returns only `@connect` + `@source` (upstream's original, unchanged)
- `mapping_directive_spec_if_applicable(version)` returns `Some(...)` only for v0.5+
- `ConnectSpecDefinition::directive_specs()` in `spec/mod.rs` conditionally appends it, since it has `self.url.version` available

This keeps upstream's function signature stable while gating `@mapping` at the spec level, not just at runtime.

### Key invariant

`@mapping` must be gated in two places:
1. **Spec level**: `directive_specifications` must not include it for pre-v0.5 (prevents directive definition injection)
2. **Runtime level**: `extract_mapping_directive_arguments` errors if `connect_spec < V0_5` (prevents processing)

Both gates are necessary. The spec-level gate prevents the directive from appearing in schemas that don't support it. The runtime gate catches any edge case where a `@mapping` directive is present but shouldn't be processed.

---

## Parser Changes: nom v8 Migration

## Root Cause

Upstream migrated from nom v7 to v8. The key API change: combinators like `ranged_span`, `opt`, `recognize`, and `tuple` used to return `impl FnMut(Input) -> Result` (callable directly). Now they return `impl Parser` (must call `.parse(input)`).

Our code was written against the old API. It auto-merged without conflict markers because it was in lines upstream didn't touch -- but it won't compile because the types changed underneath us.

## Each Change, Verified Against Upstream's Own Patterns

### 1. `recognize` + `tuple` (line 677) -- `parse_spread_type_name`

```rust
// BEFORE (ours):
recognize(tuple((
    satisfy(|c: char| c.is_ascii_uppercase()),
    take_while(|c: char| c.is_ascii_alphanumeric() || c == '_'),
)))(input)?;

// AFTER:
recognize((
    satisfy(|c: char| c.is_ascii_uppercase()),
    take_while(|c: char| c.is_ascii_alphanumeric() || c == '_'),
)).parse(input)?;
```

Two changes here: `tuple((...))` -> bare `(...)`, and `)(input)` -> `.parse(input)`.

Upstream's own `parse_identifier_no_space` at line 1854 does exactly the same thing:
```rust
recognize(pair(
    one_of("abcdef..."),
    many0(one_of("abcdef...")),
))
.parse(input)
```

Same pattern -- combinator wrapping a tuple/pair, `.parse(input)` on the outside.

### 2. `opt(Alias::parse)` (line 854) -- `parse_v0_5`

```rust
// BEFORE:
opt(Alias::parse)(input.clone())?;

// AFTER:
opt(Alias::parse).parse(input.clone())?;
```

Upstream uses `opt(...).parse(...)` elsewhere -- e.g., the `opt(ranged_span("..."))` inside the tuple at line 918 compiles because it's inside a tuple that calls `.parse()`. Standalone `opt` calls need `.parse()`.

### 3. `ranged_span("...")` (line 884) -- spread token in `parse_v0_5`

```rust
// BEFORE:
ranged_span("...")(after_spaces.clone())

// AFTER:
ranged_span("...").parse(after_spaces.clone())
```

The conflict resolution at line 1323 (which both sides agreed on) shows the canonical pattern: `ranged_span("?").parse(input.clone())`. Identical transformation.

### 4. Bare tuple (line 916) -- fallthrough spread parsing in `parse_v0_5`

```rust
// BEFORE:
tuple((
    spaces_or_comments,
    opt(ranged_span("...")),
    PathSelection::parse,
))(input.clone())

// AFTER:
(
    spaces_or_comments,
    opt(ranged_span("...")),
    PathSelection::parse,
).parse(input.clone())
```

`tuple` is gone from imports. In nom v8, a bare tuple of parsers implements `Parser` directly. The `.map(...)` chained after this call is unchanged -- it chains on the `Result`, not the parser.

### 5-7. `SpreadArgs::parse` (lines 1986, 1997, 2009)

All three are the same mechanical pattern:
```rust
// ranged_span("(")(input)  ->  ranged_span("(").parse(input)
// tuple((a, b))(input)     ->  (a, b).parse(input)
// ranged_span(")")(input)  ->  ranged_span(")").parse(input)
```

## Confidence Assessment

- Every change is the same mechanical transformation: `combinator(args)(input)` -> `combinator(args).parse(input)`, or `tuple((a,b))` -> `(a,b)`
- No logic, ordering, or semantics changed -- only the call convention
- Each one matches patterns upstream already uses in the same file
- 1192 json_selection tests pass (the same suite that was passing before)
- The conflict resolution at line 1323 serves as a "reference implementation" from upstream's own merge -- same transformation
- The nom v8 migration is purely a type-system change (FnMut -> Parser trait), not a behavioral one, so parsing semantics are identical
