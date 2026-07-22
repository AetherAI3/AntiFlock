# AntiFlock Android Guard reference

This project defines the Android Guard vertical slice in three deliberately
separate modules:

- `guard-domain`: pure Kotlin/JVM enrollment identity references, verified
  cached-policy rules, deterministic network/tunnel/DNS evaluation, fail-closed
  decisions, state transitions, exact notification copy, and scoped one-time
  bypasses.
- `platform-adapters`: ports for Android Keystore/enrollment, encrypted policy
  storage, `ConnectivityManager` observations, `VpnService` enforcement,
  notifications, and local audit storage. Recording adapters support JVM tests
  and the reference simulation.
- `reference-app`: a console composition that demonstrates blocked and restored
  states without pretending to be an installed Android VPN.

With JDK 17+ and Gradle installed:

```console
gradle test
gradle :reference-app:run
```

## Production platform work still required

No production packet transport is implemented here. `RecordingVpnPort` reports
`productionPacketTransportImplemented = false` and only records requested
fail-closed state. A device build must implement and validate:

- `VpnService` lifecycle, always-on/lockdown behavior, packet forwarding, and a
  recovery-only allowlist;
- mesh-provider or WireGuard integration and approved-exit selection;
- route-leak, DNS-path, and external-egress identity probes on real networks;
- Android Keystore key creation, QR enrollment, device credentials, revocation,
  and encrypted signed-policy persistence;
- `ConnectivityManager`/Wi-Fi permissions and behavior across supported Android
  API levels;
- notification channels/actions, boot recovery, process death, Doze, captive
  portals, handoff between cellular and Wi-Fi, and OEM-specific behavior;
- on-device tests proving ordinary egress is blocked while coordination and
  recovery endpoints remain reachable.

The notification copy intentionally states only what the observations support:

> Protection interrupted
>
> Your approved secure route is unavailable on an untrusted network. Protected
> traffic has been paused.

It does not claim active interception.
