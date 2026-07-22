package ai.aether.antiflock.guard.domain

import java.time.Duration
import java.time.Instant

enum class EnrollmentStatus { ACTIVE, SUSPENDED, REVOKED }

/**
 * Stable AntiFlock identity references. Private key bytes never belong in this
 * model; credentialAlias points to platform-protected key material.
 */
data class EnrollmentIdentity(
    val deploymentId: String,
    val nodeId: String,
    val credentialAlias: String,
    val publicKeyId: String,
    val issuedAt: Instant,
    val expiresAt: Instant?,
    val status: EnrollmentStatus,
) {
    init {
        require(deploymentId.isNotBlank())
        require(nodeId.isNotBlank())
        require(credentialAlias.isNotBlank())
        require(publicKeyId.isNotBlank())
        require(expiresAt == null || expiresAt.isAfter(issuedAt))
    }

    fun isUsable(at: Instant): Boolean =
        status == EnrollmentStatus.ACTIVE && (expiresAt == null || expiresAt.isAfter(at))
}

enum class FailMode { CLOSED }

data class GuardPolicy(
    val profileId: String,
    val requireMesh: Boolean = true,
    val requireApprovedExit: Boolean = true,
    val requireProtectedDns: Boolean = true,
    val rejectRouteLeak: Boolean = true,
    val verifyExternalExitIdentity: Boolean = true,
    val protectAllNetworks: Boolean = true,
    val allowOneTimeBypass: Boolean = true,
    val maximumObservationAge: Duration = Duration.ofSeconds(30),
    val maximumBypassDuration: Duration = Duration.ofMinutes(5),
    val failMode: FailMode = FailMode.CLOSED,
    val recoveryDestinations: Set<String> = emptySet(),
) {
    init {
        require(profileId.isNotBlank())
        require(!maximumObservationAge.isNegative && !maximumObservationAge.isZero)
        require(!maximumBypassDuration.isNegative && !maximumBypassDuration.isZero)
        require(recoveryDestinations.none(String::isBlank))
    }
}

data class SignedPolicyEnvelope(
    val revision: Long,
    val nonce: String,
    val keyId: String,
    val canonicalPayload: String,
    val signatureBase64: String,
    val issuedAt: Instant,
    val expiresAt: Instant,
    val policy: GuardPolicy,
) {
    init {
        require(revision >= 0)
        require(nonce.isNotBlank())
        require(keyId.isNotBlank())
        require(canonicalPayload.isNotBlank())
        require(signatureBase64.isNotBlank())
        require(expiresAt.isAfter(issuedAt))
    }
}

sealed interface CachedPolicyStatus {
    data object Missing : CachedPolicyStatus
    data class Active(val envelope: SignedPolicyEnvelope) : CachedPolicyStatus
    data class Expired(val envelope: SignedPolicyEnvelope) : CachedPolicyStatus
}

enum class NetworkTrust { TRUSTED, UNTRUSTED, UNKNOWN }

data class NetworkObservation(
    val observedAt: Instant,
    val networkId: String?,
    val trust: NetworkTrust,
    val meshConnected: Boolean?,
    val approvedExitActive: Boolean?,
    val dnsProtected: Boolean?,
    val routeLeakDetected: Boolean?,
    val externalExitIdentityVerified: Boolean?,
    val recoveryReachable: Boolean?,
)

data class ActionScope(
    val applicationId: String,
    val actionId: String,
    val actionType: String,
    val destinations: Set<String>,
) {
    init {
        require(applicationId.isNotBlank())
        require(actionId.isNotBlank())
        require(actionType.isNotBlank())
        require(destinations.isNotEmpty() && destinations.none(String::isBlank))
    }
}

data class ScopedBypassGrant(
    val grantId: String,
    val scope: ActionScope,
    val issuedAt: Instant,
    val expiresAt: Instant,
    val remainingUses: Int = 1,
) {
    init {
        require(grantId.isNotBlank())
        require(expiresAt.isAfter(issuedAt))
        require(remainingUses == 1)
    }
}

enum class GuardRuntimeState {
    DISCONNECTED,
    CONNECTING,
    VERIFYING,
    PROTECTED,
    DEGRADED,
    BLOCKED,
}

enum class EgressDecision { ALLOW, BLOCK, ALLOW_SCOPED_ONCE }

data class GuardEvaluationInput(
    val now: Instant,
    val identity: EnrollmentIdentity?,
    val policyStatus: CachedPolicyStatus,
    val network: NetworkObservation,
    val actionScope: ActionScope? = null,
)

data class GuardVerdict(
    val runtimeState: GuardRuntimeState,
    val egressDecision: EgressDecision,
    val reasonCodes: List<String>,
    val policyRevision: Long?,
    val consumedBypassGrantId: String? = null,
    val bypassAvailable: Boolean = false,
)

data class GuardTransition(
    val from: GuardRuntimeState,
    val to: GuardRuntimeState,
    val occurredAt: Instant,
    val reasonCodes: List<String>,
    val verdict: GuardVerdict?,
)

data class GuardNotification(
    val title: String,
    val body: String,
    val actions: List<String>,
)

object ReasonCodes {
    const val IDENTITY_UNAVAILABLE = "AF-IDENTITY-001"
    const val POLICY_MISSING = "AF-POLICY-001"
    const val POLICY_EXPIRED = "AF-POLICY-002"
    const val TELEMETRY_STALE = "AF-NODE-002"
    const val TELEMETRY_CLOCK_INVALID = "AF-NODE-003"
    const val NETWORK_TRUST_UNKNOWN = "AF-NET-003"
    const val MESH_DISCONNECTED = "AF-MESH-001"
    const val MESH_UNKNOWN = "AF-MESH-002"
    const val EXIT_UNAVAILABLE = "AF-PATH-001"
    const val EXIT_UNKNOWN = "AF-PATH-003"
    const val ROUTE_LEAK = "AF-PATH-002"
    const val ROUTE_LEAK_UNKNOWN = "AF-PATH-004"
    const val EXIT_IDENTITY_UNVERIFIED = "AF-PATH-005"
    const val EXIT_IDENTITY_UNKNOWN = "AF-PATH-006"
    const val DNS_UNPROTECTED = "AF-DNS-001"
    const val DNS_UNKNOWN = "AF-DNS-002"
    const val SCOPED_BYPASS = "AF-BYPASS-ONCE"
}
