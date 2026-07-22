package ai.aether.antiflock.guard.domain

import java.time.Duration
import java.time.Instant

sealed interface BypassConsumption {
    data class Consumed(val grantId: String) : BypassConsumption
    data object NotFound : BypassConsumption
}

class ScopedBypassRegistry {
    private val grants = linkedMapOf<String, ScopedBypassGrant>()
    private val issuedGrantIds = linkedSetOf<String>()

    @Synchronized
    fun authorize(
        grantId: String,
        scope: ActionScope,
        now: Instant,
        requestedDuration: Duration,
        policy: GuardPolicy,
    ): ScopedBypassGrant {
        require(policy.allowOneTimeBypass) { "Policy does not permit one-time bypass" }
        require(!requestedDuration.isNegative && !requestedDuration.isZero)
        require(grantId !in issuedGrantIds) { "Bypass grant ID has already been issued" }
        val duration = minOf(requestedDuration, policy.maximumBypassDuration)
        val grant = ScopedBypassGrant(
            grantId = grantId,
            scope = scope,
            issuedAt = now,
            expiresAt = now.plus(duration),
        )
        grants[grantId] = grant
        issuedGrantIds += grantId
        return grant
    }

    @Synchronized
    fun consume(scope: ActionScope, now: Instant): BypassConsumption {
        val match = grants.values.firstOrNull {
            it.scope == scope && it.expiresAt.isAfter(now) && it.remainingUses == 1
        } ?: return BypassConsumption.NotFound
        grants.remove(match.grantId)
        return BypassConsumption.Consumed(match.grantId)
    }

    @Synchronized
    fun pruneExpired(now: Instant) {
        grants.entries.removeIf { !it.value.expiresAt.isAfter(now) }
    }
}
