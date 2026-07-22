# Protobuf contracts

`antiflock/v1` is the canonical AntiFlock wire package. The source files are
hand-reviewed contracts; generated language bindings are build artifacts and
must not be edited directly.

From this directory:

```sh
buf lint
buf build
```

Once a baseline has been released, also run `buf breaking --against <baseline>`.
The configuration uses Buf's `STANDARD` lint set and `FILE` breaking policy.

## Compatibility rules

- Add fields; never renumber or reuse a published field or enum number.
- Reserve removed names and numbers.
- Treat unknown enums as unknown and fail safe. The zero value is always
  `*_UNSPECIFIED`, never a permissive decision.
- Preserve unknown fields when storing or proxying messages.
- Validate semantic constraints at ingress, including confidence `[0,1]`,
  timestamp ordering, expiry, revision, nonce, target, capability, and
  location/sensitivity policy.
- `google.protobuf.Any` event payloads use the registry in
  `../../docs/event-contracts.md`; a kind/payload mismatch is invalid.

No language-specific package option is locked yet because the public project
name and repository namespace remain unresolved. Generation tooling should set
language mappings centrally once that namespace is approved.
