package ai.aether.antiflock.guard.platform

import ai.aether.antiflock.guard.domain.ClassifiedVehicleAppearance
import ai.aether.antiflock.guard.domain.VehicleAppearanceAggregate
import ai.aether.antiflock.guard.domain.VehicleAppearanceFeature
import ai.aether.antiflock.guard.domain.VehicleAppearanceAggregateJson
import ai.aether.antiflock.guard.domain.VehicleBodyStyle
import ai.aether.antiflock.guard.domain.VehicleColorBucket
import ai.aether.antiflock.guard.domain.VehicleSizeClass
import java.time.Duration
import java.time.Instant
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AndroidVehicleAppearancePortTest {
    private var now = Instant.parse("2026-07-22T14:00:00Z")
    private var nextSessionNumber = 0
    private var nextSaltByte = 1
    private val appearance = ClassifiedVehicleAppearance(
        VehicleBodyStyle.HATCHBACK,
        VehicleSizeClass.SMALL,
        VehicleColorBucket.GREEN,
        setOf(VehicleAppearanceFeature.REAR_CARGO_RACK),
    )

    @Test
    fun `Android record boundary accepts a classified appearance and nothing else`() {
        val record = AndroidClassifiedVehicleAppearancePort::class.java.methods
            .single { it.name == "record" }
        assertEquals(listOf(ClassifiedVehicleAppearance::class.java), record.parameterTypes.toList())

        val surface = AndroidClassifiedVehicleAppearancePort::class.java.methods
            .joinToString(" ") { method ->
                method.parameterTypes.joinToString(" ") { it.typeName } + " " + method.returnType.typeName
            }
            .lowercase()
        listOf(
            "bitmap",
            "image",
            "frame",
            "embedding",
            "face",
            "plate",
            "vin",
            "ocr",
            "latitude",
            "longitude",
            "location",
        ).forEach { forbidden -> assertFalse(forbidden in surface, forbidden) }
    }

    @Test
    fun `reference adapter correlates in memory and rotates at end or fifteen minutes`() {
        val adapter = adapter()

        assertEquals(1, adapter.record(appearance).matchingCountInCurrentSession)
        assertEquals(2, adapter.record(appearance).matchingCountInCurrentSession)
        assertEquals(2, adapter.endSession())
        assertEquals(1, adapter.record(appearance).matchingCountInCurrentSession)

        now = now.plus(Duration.ofMinutes(15))
        assertEquals(1, adapter.record(appearance).matchingCountInCurrentSession)
        assertEquals(3, nextSessionNumber)
    }

    @Test
    fun `reference adapter injects expiry and purges without creating a durable token`() {
        val adapter = adapter(
            sessionLifetime = Duration.ofMinutes(10),
            observationLifetime = Duration.ofMinutes(1),
        )
        adapter.record(appearance)
        now = now.plusSeconds(61)

        assertEquals(1, adapter.purgeExpired())
        assertEquals(VehicleAppearanceAggregate.EMPTY, adapter.currentAggregate())
        val durable = VehicleAppearanceAggregateJson.encode(adapter.currentAggregate())
        assertEquals("{\"totalCount\":0,\"distinctAppearanceCount\":0,\"entries\":[]}", durable)
        assertFalse("token" in durable.lowercase())
        assertFalse("session" in durable.lowercase())
    }

    @Test
    fun `reference adapter rejects weak or reused session secret material`() {
        val weak = ReferenceInMemoryVehicleAppearancePort(
            clock = { now },
            sessionIdSource = { "weak" },
            sessionSaltSource = { ByteArray(31) },
        )
        assertFailsWith<IllegalArgumentException> { weak.record(appearance) }

        var session = 0
        val reused = ReferenceInMemoryVehicleAppearancePort(
            clock = { now },
            sessionIdSource = { "session-${++session}" },
            sessionSaltSource = { ByteArray(32) { 7 } },
        )
        reused.record(appearance)
        reused.endSession()
        assertFailsWith<IllegalStateException> { reused.record(appearance) }
    }

    @Test
    fun `adapter rejects a session configuration beyond privacy lifetime`() {
        assertFailsWith<IllegalArgumentException> {
            ReferenceInMemoryVehicleAppearancePort(
                sessionLifetime = Duration.ofMinutes(15).plusNanos(1),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            ReferenceInMemoryVehicleAppearancePort(
                sessionLifetime = Duration.ofMinutes(5),
                observationLifetime = Duration.ofMinutes(6),
            )
        }
    }

    @Test
    fun `adapter serializes concurrent observations into exact aggregate counts`() {
        val adapter = adapter()
        val executor = Executors.newFixedThreadPool(8)
        repeat(100) { executor.submit { adapter.record(appearance) } }
        executor.shutdown()

        assertTrue(executor.awaitTermination(10, TimeUnit.SECONDS))
        assertEquals(100, adapter.currentAggregate().totalCount)
        assertEquals(1, adapter.currentAggregate().distinctAppearanceCount)
    }

    @Test
    fun `reference adapter retains no filesystem or database handle`() {
        val stateTypes = ReferenceInMemoryVehicleAppearancePort::class.java.declaredFields
            .joinToString(" ") { it.type.typeName }
            .lowercase()
        listOf("java.io", "java.nio.file", "sqlite", "database", "room").forEach { forbidden ->
            assertFalse(forbidden in stateTypes, forbidden)
        }
    }

    private fun adapter(
        sessionLifetime: Duration = Duration.ofMinutes(15),
        observationLifetime: Duration = sessionLifetime,
    ) = ReferenceInMemoryVehicleAppearancePort(
        clock = { now },
        sessionIdSource = { "test-session-${++nextSessionNumber}" },
        sessionSaltSource = { ByteArray(32) { nextSaltByte.toByte() }.also { nextSaltByte++ } },
        sessionLifetime = sessionLifetime,
        observationLifetime = observationLifetime,
    )
}
