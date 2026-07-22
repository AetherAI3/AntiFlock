plugins {
    kotlin("jvm")
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    implementation(project(":guard-domain"))
    testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
}
