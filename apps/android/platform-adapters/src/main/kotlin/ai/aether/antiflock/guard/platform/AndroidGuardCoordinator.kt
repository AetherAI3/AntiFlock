package ai.aether.antiflock.guard.platform

import ai.aether.antiflock.guard.domain.ActionScope
import ai.aether.antiflock.guard.domain.CachedPolicyStatus
import ai.aether.antiflock.guard.domain.EgressDecision
import ai.aether.antiflock.guard.domain.GuardEvaluationInput
import ai.aether.antiflock.guard.domain.GuardNotificationCopy
import ai.aether.antiflock.guard.domain.GuardStateMachine
import ai.aether.antiflock.guard.domain.GuardTransition
import java.time.Instant

data class GuardCycleResult(
    val transition: GuardTransition,
    val packetTransportImplemented: Boolean,
)

class AndroidGuardCoordinator(
    private val identityPort: AndroidEnrollmentIdentityPort,
    private val policyPort: AndroidSignedPolicyPort,
    private val networkPort: AndroidNetworkObservationPort,
    private val vpnPort: AndroidVpnEnforcementPort,
    private val notificationPort: AndroidNotificationPort,
    private val auditPort: AndroidAuditPort,
    private val stateMachine: GuardStateMachine,
) {
    fun evaluate(now: Instant, actionScope: ActionScope? = null): GuardCycleResult {
        val network = networkPort.observe(now)
        val policyStatus = policyPort.currentPolicy(now)
        val transition = stateMachine.evaluate(
            GuardEvaluationInput(
                now = now,
                identity = identityPort.currentIdentity(),
                policyStatus = policyStatus,
                network = network,
                actionScope = actionScope,
            ),
        )
        val verdict = requireNotNull(transition.verdict)
        val recoveryDestinations = when (policyStatus) {
            is CachedPolicyStatus.Active -> policyStatus.envelope.policy.recoveryDestinations
            else -> emptySet()
        }
        when (verdict.egressDecision) {
            EgressDecision.ALLOW -> vpnPort.setFailClosed(false, recoveryDestinations)
            EgressDecision.BLOCK -> vpnPort.setFailClosed(true, recoveryDestinations)
            EgressDecision.ALLOW_SCOPED_ONCE -> {
                // A one-time action must never lower the global kill switch.
                vpnPort.setFailClosed(true, recoveryDestinations)
                vpnPort.allowScopedOnce(
                    scope = requireNotNull(actionScope),
                    consumedGrantId = requireNotNull(verdict.consumedBypassGrantId),
                )
            }
        }

        val notification = GuardNotificationCopy.forVerdict(verdict, network.trust)
        if (notification == null) {
            notificationPort.clearProtectionNotification()
        } else {
            notificationPort.showProtectionNotification(notification)
        }
        auditPort.append(transition, actionScope)
        return GuardCycleResult(transition, vpnPort.productionPacketTransportImplemented)
    }
}
