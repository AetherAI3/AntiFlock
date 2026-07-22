package ai.aether.antiflock.guard.platform

import ai.aether.antiflock.guard.domain.ClassifiedVehicleAppearance
import ai.aether.antiflock.guard.domain.EphemeralVehicleAppearanceCorrelator
import ai.aether.antiflock.guard.domain.VehicleAppearanceAggregate
import ai.aether.antiflock.guard.domain.VehicleAppearanceCorrelationResult
import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Duration
import java.time.Instant
import java.util.UUID

/**
 * Android-facing sink for an already-classified, coarse vehicle appearance.
 *
 * Implementations must not accept camera frames, image bytes, embeddings,
 * faces, plates, VIN/OCR text, make/model, coordinates, or free-form labels.
 * The platform classifier is intentionally outside this reference boundary.
 */
interface AndroidClassifiedVehicleAppearancePort {
    fun record(appearance: ClassifiedVehicleAppearance): VehicleAppearanceCorrelationResult

    fun currentAggregate(): VehicleAppearanceAggregate

    fun purgeExpired(): Int

    fun endSession(): Int
}

/**
 * Reference, process-memory-only adapter. It creates a fresh random HMAC secret
 * and opaque id per session, injects time and expiry, and rotates automatically
 * no later than fifteen minutes after session start.
 */
class ReferenceInMemoryVehicleAppearancePort(
    private val clock: () -> Instant = { Instant.now() },
    private val sessionIdSource: () -> String = { UUID.randomUUID().toString() },
    private val sessionSaltSource: () -> ByteArray = {
        ByteArray(EphemeralVehicleAppearanceCorrelator.MINIMUM_SESSION_SALT_BYTES).also(
            secureRandom::nextBytes,
        )
    },
    private val sessionLifetime: Duration = EphemeralVehicleAppearanceCorrelator.MAX_SESSION_LIFETIME,
    private val observationLifetime: Duration = sessionLifetime,
) : AndroidClassifiedVehicleAppearancePort {
    private var session: EphemeralVehicleAppearanceCorrelator? = null
    private var lastSaltDigest: ByteArray? = null

    init {
        require(sessionLifetime.isPositive())
        require(sessionLifetime <= EphemeralVehicleAppearanceCorrelator.MAX_SESSION_LIFETIME) {
            "Vehicle appearance sessions cannot exceed fifteen minutes"
        }
        require(observationLifetime.isPositive() && observationLifetime <= sessionLifetime)
    }

    @Synchronized
    override fun record(appearance: ClassifiedVehicleAppearance): VehicleAppearanceCorrelationResult {
        val now = clock()
        val active = activeSessionAt(now) ?: createSession(now).also { session = it }
        return active.observe(appearance, now)
    }

    @Synchronized
    override fun currentAggregate(): VehicleAppearanceAggregate {
        val now = clock()
        return activeSessionAt(now)?.aggregate(now) ?: VehicleAppearanceAggregate.EMPTY
    }

    @Synchronized
    override fun purgeExpired(): Int {
        val now = clock()
        val current = session ?: return 0
        val removed = current.purgeExpired(now)
        if (current.isExpired(now)) session = null
        return removed
    }

    @Synchronized
    override fun endSession(): Int {
        val removed = session?.endSession() ?: 0
        session = null
        return removed
    }

    private fun activeSessionAt(now: Instant): EphemeralVehicleAppearanceCorrelator? {
        val current = session ?: return null
        if (current.isExpired(now)) {
            current.endSession()
            session = null
            return null
        }
        return current
    }

    private fun createSession(now: Instant): EphemeralVehicleAppearanceCorrelator {
        val suppliedSalt = sessionSaltSource()
        require(suppliedSalt.size >= EphemeralVehicleAppearanceCorrelator.MINIMUM_SESSION_SALT_BYTES) {
            "Session salt source returned insufficient secret material"
        }
        val saltDigest = MessageDigest.getInstance("SHA-256").digest(suppliedSalt)
        check(lastSaltDigest?.let { MessageDigest.isEqual(it, saltDigest) } != true) {
            "Session salt source reused secret material"
        }
        lastSaltDigest?.fill(0)
        lastSaltDigest = saltDigest
        return try {
            EphemeralVehicleAppearanceCorrelator.start(
                sessionId = sessionIdSource(),
                sessionSalt = suppliedSalt,
                startedAt = now,
                sessionLifetime = sessionLifetime,
                observationLifetime = observationLifetime,
            )
        } finally {
            suppliedSalt.fill(0)
        }
    }

    private fun Duration.isPositive(): Boolean = !isNegative && !isZero

    private companion object {
        val secureRandom = SecureRandom()
    }
}
