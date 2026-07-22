package ai.aether.antiflock.guard.domain

import java.time.Instant

class GuardStateMachine(
    private val evaluator: GuardEvaluator,
    initialState: GuardRuntimeState = GuardRuntimeState.DISCONNECTED,
) {
    var state: GuardRuntimeState = initialState
        private set

    fun beginConnection(now: Instant): GuardTransition =
        moveTo(GuardRuntimeState.CONNECTING, now, listOf("TUNNEL_CONNECTING"), null)

    fun tunnelEstablished(now: Instant): GuardTransition =
        moveTo(GuardRuntimeState.VERIFYING, now, listOf("TUNNEL_ESTABLISHED_VERIFYING"), null)

    fun tunnelDisconnected(now: Instant): GuardTransition =
        moveTo(GuardRuntimeState.DISCONNECTED, now, listOf("TUNNEL_DISCONNECTED"), null)

    fun evaluate(input: GuardEvaluationInput): GuardTransition {
        val verdict = evaluator.evaluate(input)
        return moveTo(verdict.runtimeState, input.now, verdict.reasonCodes, verdict)
    }

    private fun moveTo(
        next: GuardRuntimeState,
        now: Instant,
        reasons: List<String>,
        verdict: GuardVerdict?,
    ): GuardTransition {
        val prior = state
        state = next
        return GuardTransition(prior, next, now, reasons, verdict)
    }
}
