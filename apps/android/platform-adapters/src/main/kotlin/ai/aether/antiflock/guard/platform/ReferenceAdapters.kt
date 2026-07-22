package ai.aether.antiflock.guard.platform

import ai.aether.antiflock.guard.domain.ActionScope
import ai.aether.antiflock.guard.domain.CachedPolicyStatus
import ai.aether.antiflock.guard.domain.EnrollmentIdentity
import ai.aether.antiflock.guard.domain.GuardNotification
import ai.aether.antiflock.guard.domain.GuardTransition
import ai.aether.antiflock.guard.domain.NetworkObservation
import java.time.Instant

class StaticIdentityPort(var identity: EnrollmentIdentity?) : AndroidEnrollmentIdentityPort {
    override fun currentIdentity(): EnrollmentIdentity? = identity
}

class StaticPolicyPort(var status: CachedPolicyStatus) : AndroidSignedPolicyPort {
    override fun currentPolicy(now: Instant): CachedPolicyStatus = status
}

class MutableNetworkPort(var observation: NetworkObservation) : AndroidNetworkObservationPort {
    override fun observe(now: Instant): NetworkObservation = observation
}

/**
 * Recording-only adapter for JVM tests and demos. It does not create a VpnService,
 * tunnel, firewall, DNS route, or packet transport.
 */
class RecordingVpnPort : AndroidVpnEnforcementPort {
    override val productionPacketTransportImplemented: Boolean = false
    var failClosed: Boolean = false
        private set
    var recoveryDestinations: Set<String> = emptySet()
        private set
    val scopedReleases = mutableListOf<Pair<ActionScope, String>>()

    override fun setFailClosed(enabled: Boolean, recoveryDestinations: Set<String>) {
        failClosed = enabled
        this.recoveryDestinations = recoveryDestinations
    }

    override fun allowScopedOnce(scope: ActionScope, consumedGrantId: String) {
        scopedReleases += scope to consumedGrantId
    }
}

class RecordingNotificationPort : AndroidNotificationPort {
    var current: GuardNotification? = null
        private set

    override fun showProtectionNotification(notification: GuardNotification) {
        current = notification
    }

    override fun clearProtectionNotification() {
        current = null
    }
}

class InMemoryAuditPort : AndroidAuditPort {
    val records = mutableListOf<Pair<GuardTransition, ActionScope?>>()

    override fun append(transition: GuardTransition, actionScope: ActionScope?) {
        records += transition to actionScope
    }
}
