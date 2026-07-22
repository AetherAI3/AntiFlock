package ai.aether.antiflock.guard.platform

import ai.aether.antiflock.guard.domain.CachedPolicyStatus
import ai.aether.antiflock.guard.domain.ActionScope
import ai.aether.antiflock.guard.domain.EgressDecision
import ai.aether.antiflock.guard.domain.EnrollmentIdentity
import ai.aether.antiflock.guard.domain.EnrollmentStatus
import ai.aether.antiflock.guard.domain.GuardEvaluator
import ai.aether.antiflock.guard.domain.GuardPolicy
import ai.aether.antiflock.guard.domain.GuardRuntimeState
import ai.aether.antiflock.guard.domain.GuardStateMachine
import ai.aether.antiflock.guard.domain.NetworkObservation
import ai.aether.antiflock.guard.domain.NetworkTrust
import ai.aether.antiflock.guard.domain.SignedPolicyEnvelope
import ai.aether.antiflock.guard.domain.ScopedBypassRegistry
import java.time.Duration
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class AndroidGuardCoordinatorTest {
    @Test
    fun `coordinator requests fail closed notification and audit then clears after restoration`() {
        val now = Instant.parse("2026-07-21T13:00:00Z")
        val policy = GuardPolicy(
            profileId = "shielded",
            recoveryDestinations = setOf("coordination.aether.example"),
        )
        val envelope = SignedPolicyEnvelope(
            revision = 7,
            nonce = "nonce-7",
            keyId = "key-1",
            canonicalPayload = "payload",
            signatureBase64 = "signature-placeholder",
            issuedAt = now.minusSeconds(60),
            expiresAt = now.plusSeconds(3600),
            policy = policy,
        )
        val network = MutableNetworkPort(
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
        val vpn = RecordingVpnPort()
        val notifications = RecordingNotificationPort()
        val audit = InMemoryAuditPort()
        val coordinator = AndroidGuardCoordinator(
            identityPort = StaticIdentityPort(
                EnrollmentIdentity(
                    deploymentId = "deployment-1",
                    nodeId = "phone-1",
                    credentialAlias = "keystore-key",
                    publicKeyId = "public-key",
                    issuedAt = now.minusSeconds(60),
                    expiresAt = null,
                    status = EnrollmentStatus.ACTIVE,
                ),
            ),
            policyPort = StaticPolicyPort(CachedPolicyStatus.Active(envelope)),
            networkPort = network,
            vpnPort = vpn,
            notificationPort = notifications,
            auditPort = audit,
            stateMachine = GuardStateMachine(GuardEvaluator()),
        )

        val blocked = coordinator.evaluate(now)
        assertEquals(GuardRuntimeState.BLOCKED, blocked.transition.to)
        assertTrue(vpn.failClosed)
        assertEquals(setOf("coordination.aether.example"), vpn.recoveryDestinations)
        assertNotNull(notifications.current)
        assertFalse(blocked.packetTransportImplemented)

        network.observation = network.observation.copy(
            observedAt = now.plusSeconds(2),
            meshConnected = true,
            approvedExitActive = true,
            dnsProtected = true,
            routeLeakDetected = false,
            externalExitIdentityVerified = true,
        )
        val restored = coordinator.evaluate(now.plusSeconds(2))
        assertEquals(GuardRuntimeState.PROTECTED, restored.transition.to)
        assertFalse(vpn.failClosed)
        assertNull(notifications.current)
        assertEquals(2, audit.records.size)
    }

    @Test
    fun `scoped bypass keeps the global kill switch enabled`() {
        val now = Instant.parse("2026-07-21T13:00:00Z")
        val policy = GuardPolicy(profileId = "shielded")
        val envelope = SignedPolicyEnvelope(
            revision = 8,
            nonce = "nonce-8",
            keyId = "key-1",
            canonicalPayload = "payload-8",
            signatureBase64 = "signature-placeholder",
            issuedAt = now.minusSeconds(60),
            expiresAt = now.plusSeconds(3600),
            policy = policy,
        )
        val scope = ActionScope(
            applicationId = "aether-messages",
            actionId = "message-1",
            actionType = "message.send",
            destinations = setOf("messages.aether.example"),
        )
        val bypasses = ScopedBypassRegistry()
        bypasses.authorize("grant-1", scope, now, Duration.ofMinutes(5), policy)
        val vpn = RecordingVpnPort()
        val notifications = RecordingNotificationPort()
        val coordinator = AndroidGuardCoordinator(
            identityPort = StaticIdentityPort(
                EnrollmentIdentity(
                    deploymentId = "deployment-1",
                    nodeId = "phone-1",
                    credentialAlias = "keystore-key",
                    publicKeyId = "public-key",
                    issuedAt = now.minusSeconds(60),
                    expiresAt = null,
                    status = EnrollmentStatus.ACTIVE,
                ),
            ),
            policyPort = StaticPolicyPort(CachedPolicyStatus.Active(envelope)),
            networkPort = MutableNetworkPort(
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
            ),
            vpnPort = vpn,
            notificationPort = notifications,
            auditPort = InMemoryAuditPort(),
            stateMachine = GuardStateMachine(GuardEvaluator(bypasses)),
        )

        val result = coordinator.evaluate(now, scope)

        assertEquals(EgressDecision.ALLOW_SCOPED_ONCE, result.transition.verdict?.egressDecision)
        assertTrue(vpn.failClosed, "a scoped bypass must not disable global fail-closed mode")
        assertEquals(listOf(scope to "grant-1"), vpn.scopedReleases)
        assertNotNull(notifications.current, "the global protection warning remains visible")
    }
}
