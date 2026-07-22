package ai.aether.antiflock.guard.domain

import java.time.Duration
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

class GuardDomainTest {
    private val now = Instant.parse("2026-07-21T13:00:00Z")
    private val identity = EnrollmentIdentity(
        deploymentId = "deployment-1",
        nodeId = "phone-1",
        credentialAlias = "android-keystore-key-1",
        publicKeyId = "public-key-1",
        issuedAt = now.minusSeconds(60),
        expiresAt = null,
        status = EnrollmentStatus.ACTIVE,
    )
    private val policy = GuardPolicy(profileId = "shielded")
    private val envelope = signedPolicy(policy = policy)

    @Test
    fun `untrusted network is protected only when mesh exit dns and leak checks pass`() {
        val verdict = GuardEvaluator().evaluate(
            input(network = protectedNetwork()),
        )

        assertEquals(GuardRuntimeState.PROTECTED, verdict.runtimeState)
        assertEquals(EgressDecision.ALLOW, verdict.egressDecision)
        assertTrue(verdict.reasonCodes.isEmpty())
        assertEquals(7, verdict.policyRevision)
    }

    @Test
    fun `missing route and unknown dns fail closed with explainable reasons`() {
        val verdict = GuardEvaluator().evaluate(
            input(
                network = protectedNetwork().copy(
                    meshConnected = false,
                    approvedExitActive = false,
                    dnsProtected = null,
                ),
            ),
        )

        assertEquals(GuardRuntimeState.BLOCKED, verdict.runtimeState)
        assertEquals(EgressDecision.BLOCK, verdict.egressDecision)
        assertTrue(ReasonCodes.MESH_DISCONNECTED in verdict.reasonCodes)
        assertTrue(ReasonCodes.EXIT_UNAVAILABLE in verdict.reasonCodes)
        assertTrue(ReasonCodes.DNS_UNKNOWN in verdict.reasonCodes)
    }

    @Test
    fun `missing identity and missing or expired policy always fail closed`() {
        val evaluator = GuardEvaluator()
        val noIdentity = evaluator.evaluate(input(identity = null))
        val noPolicy = evaluator.evaluate(input(policyStatus = CachedPolicyStatus.Missing))
        val expired = evaluator.evaluate(
            input(
                policyStatus = CachedPolicyStatus.Expired(
                    signedPolicy(expiresAt = now.minusSeconds(1)),
                ),
            ),
        )

        assertEquals(listOf(ReasonCodes.IDENTITY_UNAVAILABLE), noIdentity.reasonCodes)
        assertEquals(EgressDecision.BLOCK, noIdentity.egressDecision)
        assertEquals(listOf(ReasonCodes.POLICY_MISSING), noPolicy.reasonCodes)
        assertEquals(EgressDecision.BLOCK, noPolicy.egressDecision)
        assertEquals(listOf(ReasonCodes.POLICY_EXPIRED), expired.reasonCodes)
        assertEquals(EgressDecision.BLOCK, expired.egressDecision)
    }

    @Test
    fun `stale telemetry and unknown network trust fail closed`() {
        val verdict = GuardEvaluator().evaluate(
            input(
                network = protectedNetwork().copy(
                    observedAt = now.minusSeconds(31),
                    trust = NetworkTrust.UNKNOWN,
                ),
            ),
        )

        assertEquals(EgressDecision.BLOCK, verdict.egressDecision)
        assertTrue(ReasonCodes.TELEMETRY_STALE in verdict.reasonCodes)
        assertTrue(ReasonCodes.NETWORK_TRUST_UNKNOWN in verdict.reasonCodes)
    }

    @Test
    fun `future-dated telemetry fails closed`() {
        val verdict = GuardEvaluator().evaluate(
            input(network = protectedNetwork().copy(observedAt = now.plusSeconds(6))),
        )

        assertEquals(EgressDecision.BLOCK, verdict.egressDecision)
        assertTrue(ReasonCodes.TELEMETRY_CLOCK_INVALID in verdict.reasonCodes)
    }

    @Test
    fun `trusted network may remain degraded without fail-closed egress`() {
        val trustedDegradePolicy = policy.copy(protectAllNetworks = false)
        val verdict = GuardEvaluator().evaluate(
            input(
                policyStatus = CachedPolicyStatus.Active(
                    signedPolicy(policy = trustedDegradePolicy),
                ),
                network = protectedNetwork().copy(
                    trust = NetworkTrust.TRUSTED,
                    meshConnected = false,
                ),
            ),
        )

        assertEquals(GuardRuntimeState.DEGRADED, verdict.runtimeState)
        assertEquals(EgressDecision.ALLOW, verdict.egressDecision)
        assertTrue(ReasonCodes.MESH_DISCONNECTED in verdict.reasonCodes)
    }

    @Test
    fun `one-time bypass is exact scope and consumed once`() {
        val registry = ScopedBypassRegistry()
        val scope = ActionScope(
            applicationId = "aether-messages",
            actionId = "message-1",
            actionType = "message.send",
            destinations = setOf("messages.aether.example"),
        )
        val grant = registry.authorize(
            grantId = "grant-1",
            scope = scope,
            now = now,
            requestedDuration = Duration.ofMinutes(30),
            policy = policy,
        )
        assertEquals(now.plus(policy.maximumBypassDuration), grant.expiresAt)
        assertFailsWith<IllegalArgumentException> {
            registry.authorize(
                grantId = "grant-1",
                scope = scope,
                now = now,
                requestedDuration = Duration.ofMinutes(1),
                policy = policy,
            )
        }
        val evaluator = GuardEvaluator(registry)
        val exposedNetwork = protectedNetwork().copy(meshConnected = false)

        val wrongScope = evaluator.evaluate(
            input(
                network = exposedNetwork,
                actionScope = scope.copy(destinations = setOf("other.example")),
            ),
        )
        val first = evaluator.evaluate(input(network = exposedNetwork, actionScope = scope))
        val second = evaluator.evaluate(input(network = exposedNetwork, actionScope = scope))

        assertEquals(EgressDecision.BLOCK, wrongScope.egressDecision)
        assertEquals(EgressDecision.ALLOW_SCOPED_ONCE, first.egressDecision)
        assertEquals("grant-1", first.consumedBypassGrantId)
        assertTrue(ReasonCodes.SCOPED_BYPASS in first.reasonCodes)
        assertEquals(EgressDecision.BLOCK, second.egressDecision)
    }

    @Test
    fun `state machine exposes connection verification block and restoration transitions`() {
        val machine = GuardStateMachine(GuardEvaluator())

        assertEquals(GuardRuntimeState.CONNECTING, machine.beginConnection(now).to)
        assertEquals(GuardRuntimeState.VERIFYING, machine.tunnelEstablished(now).to)
        val blocked = machine.evaluate(
            input(network = protectedNetwork().copy(approvedExitActive = false)),
        )
        val restored = machine.evaluate(input(network = protectedNetwork()))

        assertEquals(GuardRuntimeState.BLOCKED, blocked.to)
        assertEquals(GuardRuntimeState.PROTECTED, restored.to)
        assertEquals(GuardRuntimeState.BLOCKED, restored.from)
    }

    @Test
    fun `notification copy is precise and does not claim interception`() {
        val verdict = GuardEvaluator().evaluate(
            input(network = protectedNetwork().copy(approvedExitActive = false)),
        )
        val notification = GuardNotificationCopy.forVerdict(verdict, NetworkTrust.UNTRUSTED)

        assertEquals("Protection interrupted", notification?.title)
        assertEquals(
            "Your approved secure route is unavailable on an untrusted network. Protected traffic has been paused.",
            notification?.body,
        )
        assertFalse(notification!!.body.contains("interception", ignoreCase = true))
        assertEquals(
            GuardNotificationCopy.PROTECTION_UNVERIFIED_BODY,
            GuardNotificationCopy.forVerdict(verdict, NetworkTrust.TRUSTED)?.body,
        )
    }

    @Test
    fun `unknown protection state uses uncertainty copy and does not offer unavailable bypass`() {
        val verdict = GuardEvaluator().evaluate(
            input(policyStatus = CachedPolicyStatus.Missing),
        )
        val notification = GuardNotificationCopy.forVerdict(verdict, NetworkTrust.UNTRUSTED)

        assertEquals(GuardNotificationCopy.PROTECTION_UNVERIFIED_BODY, notification?.body)
        assertFalse(notification!!.actions.contains("Send Once"))
    }

    @Test
    fun `verified policy cache rejects bad signatures rollback replay and expiry`() {
        val cache = VerifiedPolicyCache(PolicySignatureVerifier { candidate ->
            candidate.signatureBase64 == "valid-signature"
        })

        assertIs<PolicyAcceptance.InvalidSignature>(
            cache.accept(signedPolicy(signature = "invalid"), now),
        )
        assertIs<PolicyAcceptance.Accepted>(cache.accept(signedPolicy(), now))
        assertIs<PolicyAcceptance.ReplayOrRollback>(
            cache.accept(signedPolicy(revision = 7, nonce = "new-nonce"), now),
        )
        assertIs<PolicyAcceptance.AlreadyExpired>(
            cache.accept(
                signedPolicy(revision = 8, nonce = "expired", expiresAt = now),
                now,
            ),
        )
        assertIs<CachedPolicyStatus.Active>(cache.status(now))
        assertIs<CachedPolicyStatus.Expired>(cache.status(now.plusSeconds(3601)))
    }

    private fun input(
        identity: EnrollmentIdentity? = this.identity,
        policyStatus: CachedPolicyStatus = CachedPolicyStatus.Active(envelope),
        network: NetworkObservation = protectedNetwork(),
        actionScope: ActionScope? = null,
    ) = GuardEvaluationInput(now, identity, policyStatus, network, actionScope)

    private fun protectedNetwork() = NetworkObservation(
        observedAt = now,
        networkId = "coffee-shop",
        trust = NetworkTrust.UNTRUSTED,
        meshConnected = true,
        approvedExitActive = true,
        dnsProtected = true,
        routeLeakDetected = false,
        externalExitIdentityVerified = true,
        recoveryReachable = true,
    )

    private fun signedPolicy(
        revision: Long = 7,
        nonce: String = "nonce-$revision",
        signature: String = "valid-signature",
        expiresAt: Instant = now.plusSeconds(3600),
        policy: GuardPolicy = this.policy,
    ) = SignedPolicyEnvelope(
        revision = revision,
        nonce = nonce,
        keyId = "controller-key-1",
        canonicalPayload = "canonical-policy-$revision",
        signatureBase64 = signature,
        issuedAt = expiresAt.minusSeconds(3600),
        expiresAt = expiresAt,
        policy = policy,
    )
}
