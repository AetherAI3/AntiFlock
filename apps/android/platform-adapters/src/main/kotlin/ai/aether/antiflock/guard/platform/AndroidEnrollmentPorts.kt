package ai.aether.antiflock.guard.platform

import ai.aether.antiflock.guard.domain.EnrollmentIdentity
import java.time.Instant

data class EnrollmentBootstrapToken(
    val value: String,
    val expiresAt: Instant,
) {
    init {
        require(value.isNotBlank())
    }
}

data class EnrollmentPublicKey(
    val keyAlias: String,
    val algorithm: String,
    val publicKeyDerBase64: String,
) {
    init {
        require(keyAlias.isNotBlank())
        require(algorithm.isNotBlank())
        require(publicKeyDerBase64.isNotBlank())
    }
}

data class EnrollmentRequest(
    val oneTimeToken: EnrollmentBootstrapToken,
    val deviceDisplayName: String,
    val publicKey: EnrollmentPublicKey,
    val capabilities: Set<String>,
)

/** Creates non-exportable device keys in Android Keystore. */
interface AndroidEnrollmentKeyPort {
    fun createDeviceKey(keyAlias: String): EnrollmentPublicKey
}

/** Exchanges a single-use, expiring token and public key for a device identity. */
interface AndroidEnrollmentServicePort {
    fun enroll(request: EnrollmentRequest, now: Instant): EnrollmentIdentity
}
