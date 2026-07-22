plugins {
    kotlin("jvm")
    application
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    implementation(project(":guard-domain"))
    implementation(project(":platform-adapters"))
}

application {
    mainClass.set("ai.aether.antiflock.guard.reference.MainKt")
}
