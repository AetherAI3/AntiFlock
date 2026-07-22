package ai.aether.antiflock.guard.domain

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Duration
import java.time.Instant
import java.util.Collections
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * A deliberately coarse, already-classified vehicle appearance.
 *
 * This boundary cannot accept camera frames, image bytes, embeddings, faces,
 * plates, VIN/OCR text, make/model, coordinates, or free-form descriptors.
 * Classification must happen locally before this value reaches the correlator.
 */
class ClassifiedVehicleAppearance(
    val bodyStyle: VehicleBodyStyle,
    val sizeClass: VehicleSizeClass,
    val colorBucket: VehicleColorBucket,
    features: Set<VehicleAppearanceFeature> = emptySet(),
) {
    val features: Set<VehicleAppearanceFeature> =
        Collections.unmodifiableSet(features.toSet())

    init {
        require(features.size <= MAX_CONTROLLED_FEATURES) {
            "At most $MAX_CONTROLLED_FEATURES controlled appearance features are allowed"
        }
    }

    internal fun canonicalVector(): String = buildString {
        append(CANONICAL_VECTOR_VERSION)
        append("|body=")
        append(bodyStyle.name)
        append("|size=")
        append(sizeClass.name)
        append("|color=")
        append(colorBucket.name)
        append("|features=")
        append(features.map(Enum<*>::name).sorted().joinToString(","))
    }

    internal fun controlledDescription(): String = buildString {
        append(colorBucket.label)
        append(' ')
        append(sizeClass.label)
        append(' ')
        append(bodyStyle.label)
        if (features.isNotEmpty()) {
            append(" with ")
            append(features.sortedBy { it.name }.joinToString(", ") { it.label })
        }
    }

    override fun equals(other: Any?): Boolean =
        other is ClassifiedVehicleAppearance &&
            bodyStyle == other.bodyStyle &&
            sizeClass == other.sizeClass &&
            colorBucket == other.colorBucket &&
            features == other.features

    override fun hashCode(): Int {
        var result = bodyStyle.hashCode()
        result = 31 * result + sizeClass.hashCode()
        result = 31 * result + colorBucket.hashCode()
        result = 31 * result + features.hashCode()
        return result
    }

    override fun toString(): String = "ClassifiedVehicleAppearance(${controlledDescription()})"

    private companion object {
        const val CANONICAL_VECTOR_VERSION = "vehicle-appearance-v1"
        const val MAX_CONTROLLED_FEATURES = 3
    }
}

enum class VehicleBodyStyle(internal val label: String) {
    SEDAN("sedan"),
    HATCHBACK("hatchback"),
    COUPE("coupe"),
    WAGON("wagon"),
    SUV_CROSSOVER("SUV/crossover"),
    PICKUP("pickup"),
    VAN_MINIVAN("van/minivan"),
    MOTORCYCLE("motorcycle"),
    BUS("bus"),
    OTHER("other body style"),
}

enum class VehicleSizeClass(internal val label: String) {
    SMALL("small"),
    MEDIUM("medium"),
    LARGE("large"),
    OVERSIZE("oversize"),
    UNKNOWN("unknown-size"),
}

enum class VehicleColorBucket(internal val label: String) {
    BLACK("black"),
    WHITE("white"),
    GRAY_SILVER("gray/silver"),
    RED("red"),
    BLUE("blue"),
    GREEN("green"),
    BROWN_TAN("brown/tan"),
    YELLOW_ORANGE("yellow/orange"),
    OTHER("other-color"),
    UNKNOWN("unknown-color"),
}

/** A small, closed vocabulary. No text observed on the vehicle is retained. */
enum class VehicleAppearanceFeature(internal val label: String) {
    ROOF_RACK("roof rack"),
    ROOF_CARGO("roof cargo"),
    REAR_CARGO_RACK("rear cargo rack"),
    TRAILER("trailer"),
    OPEN_CARGO_BED("open cargo bed"),
    HIGH_VISIBILITY_MARKINGS("high-visibility markings"),
}

data class VehicleAppearanceAggregateEntry(
    val count: Int,
    val text: String,
) {
    init {
        require(count > 0)
        require(text.isNotBlank())
    }
}

/**
 * The only durable-facing vehicle result: aggregate counts and controlled text.
 * It intentionally contains no correlation token, session metadata, observation
 * timestamps, or stable identifier.
 */
data class VehicleAppearanceAggregate(
    val totalCount: Int,
    val distinctAppearanceCount: Int,
    val entries: List<VehicleAppearanceAggregateEntry>,
) {
    init {
        require(totalCount >= 0)
        require(distinctAppearanceCount >= 0)
        require(distinctAppearanceCount == entries.size)
        require(totalCount == entries.sumOf { it.count })
    }

    companion object {
        val EMPTY = VehicleAppearanceAggregate(0, 0, emptyList())
    }
}

/** Counts-only result for immediate, local correlation feedback. */
data class VehicleAppearanceCorrelationResult(
    val matchingCountInCurrentSession: Int,
    val aggregate: VehicleAppearanceAggregate,
) {
    init {
        require(matchingCountInCurrentSession > 0)
    }
}

/**
 * Explicit durable serializer. The schema is intentionally restricted to
 * aggregate counts and descriptions derived from the closed enums above.
 */
object VehicleAppearanceAggregateJson {
    fun encode(aggregate: VehicleAppearanceAggregate): String = buildString {
        append("{\"totalCount\":")
        append(aggregate.totalCount)
        append(",\"distinctAppearanceCount\":")
        append(aggregate.distinctAppearanceCount)
        append(",\"entries\":[")
        aggregate.entries.forEachIndexed { index, entry ->
            if (index > 0) append(',')
            append("{\"count\":")
            append(entry.count)
            append(",\"text\":\"")
            append(jsonEscape(entry.text))
            append("\"}")
        }
        append("]}")
    }

    private fun jsonEscape(value: String): String = buildString(value.length) {
        value.forEach { character ->
            when (character) {
                '\\' -> append("\\\\")
                '"' -> append("\\\"")
                '\b' -> append("\\b")
                '\u000C' -> append("\\f")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                else -> if (character.code < 0x20) {
                    append("\\u")
                    append(character.code.toString(16).padStart(4, '0'))
                } else {
                    append(character)
                }
            }
        }
    }
}

/**
 * In-memory-only correlator for one observation session.
 *
 * The HMAC secret is copied on entry and zeroed when the session ends. HMAC
 * tokens remain private map keys and are never returned or serialized.
 */
class EphemeralVehicleAppearanceCorrelator private constructor(
    private val sessionId: String,
    sessionSalt: ByteArray,
    private val startedAt: Instant,
    private val sessionExpiresAt: Instant,
    private val observationLifetime: Duration,
) {
    private val secret = sessionSalt.copyOf()
    private val buckets = linkedMapOf<DestroyableToken, ObservationBucket>()
    private var ended = false
    private var lastObservedAt = startedAt

    fun observe(
        appearance: ClassifiedVehicleAppearance,
        observedAt: Instant,
    ): VehicleAppearanceCorrelationResult {
        check(!ended) { "Vehicle appearance session has ended" }
        require(!observedAt.isBefore(startedAt)) { "Observation predates the session" }
        require(!observedAt.isBefore(lastObservedAt)) { "Observation time must be monotonic" }
        require(observedAt.isBefore(sessionExpiresAt)) { "Vehicle appearance session has expired" }
        purgeExpired(observedAt)
        check(!ended) { "Vehicle appearance session has ended" }

        lastObservedAt = observedAt
        val observationExpiresAt = minOf(
            observedAt.plus(observationLifetime),
            sessionExpiresAt,
        )
        val probe = DestroyableToken(
            VehicleAppearanceHmac.digest(sessionId, secret, appearance),
        )
        val existing = buckets[probe]
        val bucket = if (existing == null) {
            ObservationBucket(appearance).also { buckets[probe] = it }
        } else {
            probe.destroy()
            existing
        }
        bucket.observations += EphemeralObservation(
            sessionId = sessionId,
            observedAt = observedAt,
            expiresAt = observationExpiresAt,
        )

        return VehicleAppearanceCorrelationResult(
            matchingCountInCurrentSession = bucket.observations.size,
            aggregate = aggregateWithoutPurging(),
        )
    }

    fun aggregate(at: Instant): VehicleAppearanceAggregate {
        purgeExpired(at)
        return aggregateWithoutPurging()
    }

    /** Removes expired observations, or destroys the entire session at expiry. */
    fun purgeExpired(at: Instant): Int {
        if (ended) return 0
        if (!at.isBefore(sessionExpiresAt)) return endSession()

        var removed = 0
        val iterator = buckets.entries.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next()
            val before = entry.value.observations.size
            entry.value.observations.removeAll { !it.expiresAt.isAfter(at) }
            removed += before - entry.value.observations.size
            if (entry.value.observations.isEmpty()) {
                iterator.remove()
                entry.key.destroy()
            }
        }
        return removed
    }

    /** Ends the session immediately and zeroes all retained secret material. */
    fun endSession(): Int {
        if (ended) return 0
        val removed = buckets.values.sumOf { it.observations.size }
        val tokens = buckets.keys.toList()
        buckets.clear()
        tokens.forEach(DestroyableToken::destroy)
        secret.fill(0)
        ended = true
        return removed
    }

    fun isExpired(at: Instant): Boolean = ended || !at.isBefore(sessionExpiresAt)

    private fun aggregateWithoutPurging(): VehicleAppearanceAggregate {
        if (ended || buckets.isEmpty()) return VehicleAppearanceAggregate.EMPTY
        val entries = buckets.values
            .map { bucket ->
                VehicleAppearanceAggregateEntry(
                    count = bucket.observations.size,
                    text = bucket.appearance.controlledDescription(),
                )
            }
            .sortedWith(compareByDescending<VehicleAppearanceAggregateEntry> { it.count }.thenBy { it.text })
        return VehicleAppearanceAggregate(
            totalCount = entries.sumOf { it.count },
            distinctAppearanceCount = entries.size,
            entries = entries,
        )
    }

    private data class EphemeralObservation(
        val sessionId: String,
        val observedAt: Instant,
        val expiresAt: Instant,
    )

    private class ObservationBucket(
        val appearance: ClassifiedVehicleAppearance,
        val observations: MutableList<EphemeralObservation> = mutableListOf(),
    )

    companion object {
        val MAX_SESSION_LIFETIME: Duration = Duration.ofMinutes(15)
        const val MINIMUM_SESSION_SALT_BYTES: Int = 32

        fun start(
            sessionId: String,
            sessionSalt: ByteArray,
            startedAt: Instant,
            sessionLifetime: Duration = MAX_SESSION_LIFETIME,
            observationLifetime: Duration = sessionLifetime,
        ): EphemeralVehicleAppearanceCorrelator {
            require(sessionId.isNotBlank() && sessionId.length <= 128) {
                "Session id must be present and bounded"
            }
            require(sessionId.none(Char::isISOControl)) { "Session id cannot contain control characters" }
            require(sessionSalt.size >= MINIMUM_SESSION_SALT_BYTES) {
                "Vehicle appearance sessions require at least $MINIMUM_SESSION_SALT_BYTES bytes of secret material"
            }
            require(sessionLifetime.isPositive() && sessionLifetime <= MAX_SESSION_LIFETIME) {
                "Vehicle appearance sessions must end within $MAX_SESSION_LIFETIME"
            }
            require(observationLifetime.isPositive() && observationLifetime <= sessionLifetime) {
                "Observation lifetime must be positive and no longer than the session"
            }
            return EphemeralVehicleAppearanceCorrelator(
                sessionId = sessionId,
                sessionSalt = sessionSalt,
                startedAt = startedAt,
                sessionExpiresAt = startedAt.plus(sessionLifetime),
                observationLifetime = observationLifetime,
            )
        }

        private fun Duration.isPositive(): Boolean = !isNegative && !isZero
    }
}

internal object VehicleAppearanceHmac {
    fun digest(
        sessionId: String,
        sessionSalt: ByteArray,
        appearance: ClassifiedVehicleAppearance,
    ): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(sessionSalt, "HmacSHA256"))
        return mac.doFinal(
            "$sessionId\u001f${appearance.canonicalVector()}".toByteArray(StandardCharsets.UTF_8),
        )
    }
}

private class DestroyableToken(private val bytes: ByteArray) {
    private val stableHashCode = bytes.contentHashCode()

    fun destroy() {
        bytes.fill(0)
    }

    override fun equals(other: Any?): Boolean =
        other is DestroyableToken && MessageDigest.isEqual(bytes, other.bytes)

    override fun hashCode(): Int = stableHashCode
}
