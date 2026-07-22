package ai.aether.antiflock.guard.reference

import ai.aether.antiflock.guard.domain.CachedPolicyStatus
import ai.aether.antiflock.guard.domain.EnrollmentIdentity
import ai.aether.antiflock.guard.domain.EnrollmentStatus
import ai.aether.antiflock.guard.domain.GuardEvaluator
import ai.aether.antiflock.guard.domain.GuardPolicy
import ai.aether.antiflock.guard.domain.GuardStateMachine
import ai.aether.antiflock.guard.domain.NetworkObservation
import ai.aether.antiflock.guard.domain.NetworkTrust
import ai.aether.antiflock.guard.domain.SignedPolicyEnvelope
import ai.aether.antiflock.guard.platform.AndroidGuardCoordinator
import ai.aether.antiflock.guard.platform.InMemoryAuditPort
import ai.aether.antiflock.guard.platform.MutableNetworkPort
import ai.aether.antiflock.guard.platform.RecordingNotificationPort
import ai.aether.antiflock.guard.platform.RecordingVpnPort
import ai.aether.antiflock.guard.platform.StaticIdentityPort
import ai.aether.antiflock.guard.platform.StaticPolicyPort
import java.time.Instant

fun main() {
    val now = Instant.parse("2026-07-21T13:00:00Z")
    val policy = GuardPolicy(
        profileId = "shielded",
        recoveryDestinations = setOf("coordination.aether.example"),
    )
    val signedPolicy = SignedPolicyEnvelope(
        revision = 7,
        nonce = "demo-policy-nonce",
        keyId = "demo-controller-key",
        canonicalPayload = "demo-only-canonical-policy",
        signatureBase64 = "demo-signature-placeholder",
        issuedAt = now.minusSeconds(60),
        expiresAt = now.plusSeconds(3600),
        policy = policy,
    )
    val networkPort = MutableNetworkPort(
        NetworkObservation(
            observedAt = now,
            networkId = "coffee-shop",
            trust = NetworkTrust.UNTRUSTED,
            meshConnected = false,
            approvedExitActive = false,
            dnsProtected = null,
            routeLeakDetected = null,
            externalExitIdentityVerified = false,
            recoveryReachable = true,
        ),
    )
    val vpnPort = RecordingVpnPort()
    val notificationPort = RecordingNotificationPort()
    val auditPort = InMemoryAuditPort()
    val coordinator = AndroidGuardCoordinator(
        identityPort = StaticIdentityPort(
            EnrollmentIdentity(
                deploymentId = "demo-deployment",
                nodeId = "demo-phone",
                credentialAlias = "android-keystore-alias-placeholder",
                publicKeyId = "demo-public-key",
                issuedAt = now.minusSeconds(60),
                expiresAt = null,
                status = EnrollmentStatus.ACTIVE,
            ),
        ),
        policyPort = StaticPolicyPort(CachedPolicyStatus.Active(signedPolicy)),
        networkPort = networkPort,
        vpnPort = vpnPort,
        notificationPort = notificationPort,
        auditPort = auditPort,
        stateMachine = GuardStateMachine(GuardEvaluator()),
    )

    val blocked = coordinator.evaluate(now)
    println("Android Guard reference simulation")
    println("Packet/VPN transport implemented: ${blocked.packetTransportImplemented}")
    println("State: ${blocked.transition.to}; failClosed=${vpnPort.failClosed}")
    println(notificationPort.current?.title)
    println(notificationPort.current?.body)

    networkPort.observation = networkPort.observation.copy(
        observedAt = now.plusSeconds(3),
        meshConnected = true,
        approvedExitActive = true,
        dnsProtected = true,
        routeLeakDetected = false,
        externalExitIdentityVerified = true,
    )
    val restored = coordinator.evaluate(now.plusSeconds(3))
    println("State after verified restoration: ${restored.transition.to}; failClosed=${vpnPort.failClosed}")
    println("Audit transitions: ${auditPort.records.size}")
}
