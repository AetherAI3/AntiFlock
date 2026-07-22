package ai.aether.antiflock.guard.platform

import ai.aether.antiflock.guard.domain.ActionScope
import ai.aether.antiflock.guard.domain.CachedPolicyStatus
import ai.aether.antiflock.guard.domain.EnrollmentIdentity
import ai.aether.antiflock.guard.domain.GuardNotification
import ai.aether.antiflock.guard.domain.GuardTransition
import ai.aether.antiflock.guard.domain.NetworkObservation
import java.time.Instant

/** Implement with Android Keystore plus the enrollment API. */
interface AndroidEnrollmentIdentityPort {
    fun currentIdentity(): EnrollmentIdentity?
}

/** Implement with encrypted local storage and signature verification. */
interface AndroidSignedPolicyPort {
    fun currentPolicy(now: Instant): CachedPolicyStatus
}

/** Implement with ConnectivityManager, WifiInfo, tunnel, route, and DNS probes. */
interface AndroidNetworkObservationPort {
    fun observe(now: Instant): NetworkObservation
}

/**
 * Implement with Android VpnService or a supported mesh provider. A production
 * adapter must keep recovery traffic reachable and prove there is no route leak.
 */
interface AndroidVpnEnforcementPort {
    val productionPacketTransportImplemented: Boolean

    fun setFailClosed(enabled: Boolean, recoveryDestinations: Set<String>)

    /** Keep fail-closed active and release only this exact, already-consumed grant. */
    fun allowScopedOnce(scope: ActionScope, consumedGrantId: String)
}

/** Implement with NotificationManager and a dedicated protection channel. */
interface AndroidNotificationPort {
    fun showProtectionNotification(notification: GuardNotification)
    fun clearProtectionNotification()
}

/** Implement with an append-only, device-local audit store and eventual upload. */
interface AndroidAuditPort {
    fun append(transition: GuardTransition, actionScope: ActionScope?)
}
