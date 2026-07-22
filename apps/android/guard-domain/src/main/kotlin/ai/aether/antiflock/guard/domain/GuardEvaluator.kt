package ai.aether.antiflock.guard.domain

class GuardEvaluator(
    private val bypassRegistry: ScopedBypassRegistry = ScopedBypassRegistry(),
) {
    fun evaluate(input: GuardEvaluationInput): GuardVerdict {
        if (input.identity?.isUsable(input.now) != true) {
            return blocked(listOf(ReasonCodes.IDENTITY_UNAVAILABLE), null)
        }

        val activePolicy = when (val policyStatus = input.policyStatus) {
            CachedPolicyStatus.Missing -> return blocked(listOf(ReasonCodes.POLICY_MISSING), null)
            is CachedPolicyStatus.Expired -> return blocked(
                listOf(ReasonCodes.POLICY_EXPIRED),
                policyStatus.envelope.revision,
            )
            is CachedPolicyStatus.Active -> policyStatus.envelope
        }
        val policy = activePolicy.policy
        val reasons = mutableListOf<String>()

        if (input.network.observedAt.plus(policy.maximumObservationAge).isBefore(input.now)) {
            reasons += ReasonCodes.TELEMETRY_STALE
        }
        if (input.network.observedAt.isAfter(input.now.plusSeconds(5))) {
            reasons += ReasonCodes.TELEMETRY_CLOCK_INVALID
        }
        if (input.network.trust == NetworkTrust.UNKNOWN) {
            reasons += ReasonCodes.NETWORK_TRUST_UNKNOWN
        }

        val enforcementRequired =
            policy.protectAllNetworks || input.network.trust != NetworkTrust.TRUSTED

        if (policy.requireMesh) {
            when (input.network.meshConnected) {
                false -> reasons += ReasonCodes.MESH_DISCONNECTED
                null -> reasons += ReasonCodes.MESH_UNKNOWN
                true -> Unit
            }
        }
        if (policy.requireApprovedExit) {
            when (input.network.approvedExitActive) {
                false -> reasons += ReasonCodes.EXIT_UNAVAILABLE
                null -> reasons += ReasonCodes.EXIT_UNKNOWN
                true -> Unit
            }
        }
        if (policy.requireProtectedDns) {
            when (input.network.dnsProtected) {
                false -> reasons += ReasonCodes.DNS_UNPROTECTED
                null -> reasons += ReasonCodes.DNS_UNKNOWN
                true -> Unit
            }
        }
        if (policy.rejectRouteLeak) {
            when (input.network.routeLeakDetected) {
                true -> reasons += ReasonCodes.ROUTE_LEAK
                null -> reasons += ReasonCodes.ROUTE_LEAK_UNKNOWN
                false -> Unit
            }
        }
        if (policy.verifyExternalExitIdentity) {
            when (input.network.externalExitIdentityVerified) {
                false -> reasons += ReasonCodes.EXIT_IDENTITY_UNVERIFIED
                null -> reasons += ReasonCodes.EXIT_IDENTITY_UNKNOWN
                true -> Unit
            }
        }

        val distinctReasons = reasons.distinct()
        if (distinctReasons.isEmpty()) {
                return GuardVerdict(
                runtimeState = GuardRuntimeState.PROTECTED,
                egressDecision = EgressDecision.ALLOW,
                reasonCodes = emptyList(),
                policyRevision = activePolicy.revision,
            )
        }

        if (!enforcementRequired) {
            return GuardVerdict(
                runtimeState = GuardRuntimeState.DEGRADED,
                egressDecision = EgressDecision.ALLOW,
                reasonCodes = distinctReasons,
                policyRevision = activePolicy.revision,
            )
        }

        if (policy.allowOneTimeBypass && input.actionScope != null) {
            when (val consumed = bypassRegistry.consume(input.actionScope, input.now)) {
                is BypassConsumption.Consumed -> return GuardVerdict(
                    runtimeState = GuardRuntimeState.BLOCKED,
                    egressDecision = EgressDecision.ALLOW_SCOPED_ONCE,
                    reasonCodes = distinctReasons + ReasonCodes.SCOPED_BYPASS,
                    policyRevision = activePolicy.revision,
                    consumedBypassGrantId = consumed.grantId,
                    bypassAvailable = true,
                )
                BypassConsumption.NotFound -> Unit
            }
        }

        return blocked(
            reasons = distinctReasons,
            revision = activePolicy.revision,
            bypassAvailable = policy.allowOneTimeBypass,
        )
    }

    private fun blocked(
        reasons: List<String>,
        revision: Long?,
        bypassAvailable: Boolean = false,
    ): GuardVerdict = GuardVerdict(
        runtimeState = GuardRuntimeState.BLOCKED,
        egressDecision = EgressDecision.BLOCK,
        reasonCodes = reasons,
        policyRevision = revision,
        bypassAvailable = bypassAvailable,
    )
}
