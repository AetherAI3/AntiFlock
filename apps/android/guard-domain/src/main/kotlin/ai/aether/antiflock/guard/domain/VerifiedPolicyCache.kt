package ai.aether.antiflock.guard.domain

import java.time.Duration
import java.time.Instant

/** The verifier must bind policy, canonicalPayload, keyId, and signature. */
fun interface PolicySignatureVerifier {
    fun verify(envelope: SignedPolicyEnvelope): Boolean
}

sealed interface PolicyAcceptance {
    data class Accepted(val revision: Long) : PolicyAcceptance
    data object InvalidSignature : PolicyAcceptance
    data object AlreadyExpired : PolicyAcceptance
    data object IssuedTooFarInFuture : PolicyAcceptance
    data object ReplayOrRollback : PolicyAcceptance
    data object NonceReplay : PolicyAcceptance
}

class VerifiedPolicyCache(
    private val signatureVerifier: PolicySignatureVerifier,
    private val allowedClockSkew: Duration = Duration.ofMinutes(5),
) {
    private var cached: SignedPolicyEnvelope? = null
    private val acceptedNonces = linkedSetOf<String>()

    @Synchronized
    fun accept(candidate: SignedPolicyEnvelope, now: Instant): PolicyAcceptance {
        if (!signatureVerifier.verify(candidate)) return PolicyAcceptance.InvalidSignature
        if (!candidate.expiresAt.isAfter(now)) return PolicyAcceptance.AlreadyExpired
        if (candidate.issuedAt.isAfter(now.plus(allowedClockSkew))) {
            return PolicyAcceptance.IssuedTooFarInFuture
        }
        val current = cached
        if (current != null && candidate.revision <= current.revision) {
            return PolicyAcceptance.ReplayOrRollback
        }
        if (candidate.nonce in acceptedNonces) return PolicyAcceptance.NonceReplay

        cached = candidate
        acceptedNonces += candidate.nonce
        return PolicyAcceptance.Accepted(candidate.revision)
    }

    @Synchronized
    fun status(now: Instant): CachedPolicyStatus {
        val current = cached ?: return CachedPolicyStatus.Missing
        return if (current.expiresAt.isAfter(now)) {
            CachedPolicyStatus.Active(current)
        } else {
            CachedPolicyStatus.Expired(current)
        }
    }
}
