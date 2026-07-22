package ai.aether.antiflock.guard.domain

import java.lang.reflect.Modifier
import java.time.Duration
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class VehicleAppearancePrivacyTest {
    private val startedAt = Instant.parse("2026-07-22T12:00:00Z")
    private val salt = ByteArray(32) { it.toByte() }
    private val blueSuv = ClassifiedVehicleAppearance(
        bodyStyle = VehicleBodyStyle.SUV_CROSSOVER,
        sizeClass = VehicleSizeClass.MEDIUM,
        colorBucket = VehicleColorBucket.BLUE,
        features = setOf(
            VehicleAppearanceFeature.ROOF_RACK,
            VehicleAppearanceFeature.ROOF_CARGO,
        ),
    )

    @Test
    fun `HMAC uses canonical coarse vector and is scoped to one session`() {
        val reordered = ClassifiedVehicleAppearance(
            bodyStyle = VehicleBodyStyle.SUV_CROSSOVER,
            sizeClass = VehicleSizeClass.MEDIUM,
            colorBucket = VehicleColorBucket.BLUE,
            features = linkedSetOf(
                VehicleAppearanceFeature.ROOF_CARGO,
                VehicleAppearanceFeature.ROOF_RACK,
            ),
        )

        val first = VehicleAppearanceHmac.digest("session-a", salt, blueSuv)
        val canonicalEquivalent = VehicleAppearanceHmac.digest("session-a", salt, reordered)
        val otherSession = VehicleAppearanceHmac.digest("session-b", salt, blueSuv)
        val otherSecret = VehicleAppearanceHmac.digest(
            "session-a",
            ByteArray(32) { (it + 1).toByte() },
            blueSuv,
        )

        assertEquals(
            "7687da42ca6fcddbc9a221a645bfe32370cb79546b274bf51520c8df94f88fdf",
            first.toHex(),
        )
        assertContentEquals(first, canonicalEquivalent)
        assertNotEquals(first.toHex(), otherSession.toHex())
        assertNotEquals(first.toHex(), otherSecret.toHex())
    }

    @Test
    fun `classification copies controlled features and rejects over-specific feature sets`() {
        val mutableFeatures = mutableSetOf(VehicleAppearanceFeature.ROOF_RACK)
        val appearance = ClassifiedVehicleAppearance(
            VehicleBodyStyle.WAGON,
            VehicleSizeClass.MEDIUM,
            VehicleColorBucket.GRAY_SILVER,
            mutableFeatures,
        )
        mutableFeatures += VehicleAppearanceFeature.TRAILER

        assertEquals(setOf(VehicleAppearanceFeature.ROOF_RACK), appearance.features)
        assertFailsWith<IllegalArgumentException> {
            ClassifiedVehicleAppearance(
                VehicleBodyStyle.PICKUP,
                VehicleSizeClass.LARGE,
                VehicleColorBucket.WHITE,
                setOf(
                    VehicleAppearanceFeature.ROOF_RACK,
                    VehicleAppearanceFeature.ROOF_CARGO,
                    VehicleAppearanceFeature.REAR_CARGO_RACK,
                    VehicleAppearanceFeature.TRAILER,
                ),
            )
        }
    }

    @Test
    fun `same-session correlation returns counts while a new session cannot reuse the correlation`() {
        val firstSession = correlator("session-a")

        val first = firstSession.observe(blueSuv, startedAt)
        val second = firstSession.observe(blueSuv, startedAt.plusSeconds(1))
        assertEquals(1, first.matchingCountInCurrentSession)
        assertEquals(2, second.matchingCountInCurrentSession)
        assertEquals(2, second.aggregate.totalCount)
        assertEquals(1, second.aggregate.distinctAppearanceCount)
        assertEquals("blue medium SUV/crossover with roof cargo, roof rack", second.aggregate.entries.single().text)

        assertEquals(2, firstSession.endSession())
        assertFailsWith<IllegalStateException> {
            firstSession.observe(blueSuv, startedAt.plusSeconds(2))
        }

        val nextSession = correlator("session-b")
        val afterRotation = nextSession.observe(blueSuv, startedAt.plusSeconds(2))
        assertEquals(1, afterRotation.matchingCountInCurrentSession)
        assertEquals(1, afterRotation.aggregate.totalCount)
    }

    @Test
    fun `observation expiry purges individual records and session expiry purges everything`() {
        val session = EphemeralVehicleAppearanceCorrelator.start(
            sessionId = "session-a",
            sessionSalt = salt,
            startedAt = startedAt,
            sessionLifetime = Duration.ofMinutes(10),
            observationLifetime = Duration.ofMinutes(1),
        )
        val redSedan = ClassifiedVehicleAppearance(
            VehicleBodyStyle.SEDAN,
            VehicleSizeClass.MEDIUM,
            VehicleColorBucket.RED,
        )
        session.observe(blueSuv, startedAt)
        session.observe(redSedan, startedAt.plusSeconds(30))

        assertEquals(1, session.purgeExpired(startedAt.plusSeconds(61)))
        assertEquals(1, session.aggregate(startedAt.plusSeconds(61)).totalCount)
        assertEquals(1, session.purgeExpired(startedAt.plus(Duration.ofMinutes(10))))
        assertTrue(session.isExpired(startedAt.plus(Duration.ofMinutes(10))))
        assertEquals(VehicleAppearanceAggregate.EMPTY, session.aggregate(startedAt.plus(Duration.ofMinutes(11))))
    }

    @Test
    fun `session enforces secret size fifteen minute cap and trustworthy time ordering`() {
        assertFailsWith<IllegalArgumentException> {
            EphemeralVehicleAppearanceCorrelator.start(
                "short-secret",
                ByteArray(31),
                startedAt,
            )
        }
        assertFailsWith<IllegalArgumentException> {
            EphemeralVehicleAppearanceCorrelator.start(
                "too-long",
                salt,
                startedAt,
                sessionLifetime = Duration.ofMinutes(15).plusNanos(1),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            EphemeralVehicleAppearanceCorrelator.start(
                "bad-retention",
                salt,
                startedAt,
                sessionLifetime = Duration.ofMinutes(5),
                observationLifetime = Duration.ofMinutes(6),
            )
        }

        val session = correlator("bounded")
        session.observe(blueSuv, startedAt.plusSeconds(2))
        assertFailsWith<IllegalArgumentException> {
            session.observe(blueSuv, startedAt.plusSeconds(1))
        }
        assertFailsWith<IllegalArgumentException> {
            correlator("expired").observe(blueSuv, startedAt.plus(Duration.ofMinutes(15)))
        }
    }

    @Test
    fun `classified input API has no raw or identifying capture fields`() {
        val fields = ClassifiedVehicleAppearance::class.java.declaredFields
            .filterNot { it.isSynthetic || Modifier.isStatic(it.modifiers) }
        assertEquals(
            setOf("bodyStyle", "sizeClass", "colorBucket", "features"),
            fields.map { it.name }.toSet(),
        )
        assertTrue(fields.none { it.type == ByteArray::class.java })
        assertTrue(fields.none { it.type == FloatArray::class.java })
        assertTrue(fields.none { it.type == DoubleArray::class.java })
        assertTrue(fields.none { it.type == String::class.java })

        val forbiddenNames = listOf(
            "image",
            "frame",
            "embedding",
            "face",
            "plate",
            "vin",
            "ocr",
            "make",
            "model",
            "location",
            "latitude",
            "longitude",
            "descriptor",
        )
        val publicSurface = fields.joinToString(" ") { "${it.name} ${it.type.name}" }.lowercase()
        forbiddenNames.forEach { forbidden -> assertFalse(forbidden in publicSurface, forbidden) }
    }

    @Test
    fun `durable JSON contains aggregate counts and controlled text only`() {
        val session = correlator("serialization-session")
        session.observe(blueSuv, startedAt)
        val aggregate = session.observe(blueSuv, startedAt.plusSeconds(1)).aggregate

        val encoded = VehicleAppearanceAggregateJson.encode(aggregate)

        assertEquals(
            "{\"totalCount\":2,\"distinctAppearanceCount\":1," +
                "\"entries\":[{\"count\":2,\"text\":\"blue medium SUV/crossover with roof cargo, roof rack\"}]}",
            encoded,
        )
        listOf(
            "token",
            "hmac",
            "session",
            "observed",
            "expires",
            "image",
            "embedding",
            "face",
            "plate",
            "vin",
            "ocr",
            "make",
            "model",
            "location",
            "latitude",
            "longitude",
            "descriptor",
        ).forEach { forbidden -> assertFalse(forbidden in encoded.lowercase(), forbidden) }
    }

    private fun correlator(sessionId: String) = EphemeralVehicleAppearanceCorrelator.start(
        sessionId = sessionId,
        sessionSalt = salt,
        startedAt = startedAt,
    )

    private fun ByteArray.toHex(): String = joinToString("") {
        (it.toInt() and 0xff).toString(16).padStart(2, '0')
    }
}
