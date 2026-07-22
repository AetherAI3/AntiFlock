package ai.aether.antiflock.guard.domain

object GuardNotificationCopy {
    const val PROTECTION_INTERRUPTED_TITLE = "Protection interrupted"
    const val PROTECTION_INTERRUPTED_BODY =
        "Your approved secure route is unavailable on an untrusted network. Protected traffic has been paused."
    const val PROTECTION_UNVERIFIED_BODY =
        "AntiFlock cannot verify the current protection policy and network path. Protected traffic has been paused."

    fun forVerdict(verdict: GuardVerdict, trust: NetworkTrust): GuardNotification? {
        if (verdict.runtimeState != GuardRuntimeState.BLOCKED) {
            return null
        }
        val routeEvidence = verdict.reasonCodes.any {
            it.startsWith("AF-MESH-") || it.startsWith("AF-PATH-") || it.startsWith("AF-DNS-")
        }
        val preciseCoffeeShopCopy = trust == NetworkTrust.UNTRUSTED && routeEvidence
        val actions = buildList {
            add("Restore Shield")
            if (verdict.bypassAvailable) add("Send Once")
            add("View Environment")
        }
        return GuardNotification(
            title = PROTECTION_INTERRUPTED_TITLE,
            body = if (preciseCoffeeShopCopy) {
                PROTECTION_INTERRUPTED_BODY
            } else {
                PROTECTION_UNVERIFIED_BODY
            },
            actions = actions,
        )
    }
}
