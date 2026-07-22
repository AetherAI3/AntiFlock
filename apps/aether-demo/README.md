# Aether coffee-shop demonstration

This CLI demonstrates the application-integrated AntiFlock path:

1. An Aether message is described to the Secure Action SDK without exposing its
   body.
2. The simulated local agent returns `HOLD` because the device is on an
   untrusted network without its approved route.
3. The application shows the precise protection warning and keeps the message
   pending.
4. The simulated guard restores and verifies mesh, exit, and DNS state.
5. The SDK re-evaluates the same action, receives `ALLOW`, sends it, and records
   the lifecycle.

Run it after installing dependencies:

```console
npm install
npm run demo
```

This is a deterministic control-plane demonstration. It does **not** implement
or claim a VPN, packet tunnel, DNS resolver, or production local-agent service.
Those capabilities belong behind the platform and transport adapters.
