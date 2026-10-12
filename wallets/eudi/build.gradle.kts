// A minimal HTTP wallet on the EUDI reference libraries, driven by vcit.
plugins {
    kotlin("jvm") version "2.2.21"
    kotlin("plugin.serialization") version "2.2.21"
    application
}

repositories { mavenCentral() }

val ktor = "3.3.3"

dependencies {
    implementation("eu.europa.ec.eudi:eudi-lib-jvm-openid4vp-kt:0.16.2")
    implementation("io.ktor:ktor-server-netty:$ktor")
    implementation("io.ktor:ktor-server-content-negotiation:$ktor")
    implementation("io.ktor:ktor-client-okhttp:$ktor")
    implementation("io.ktor:ktor-client-content-negotiation:$ktor")
    implementation("io.ktor:ktor-serialization-kotlinx-json:$ktor")
    implementation("org.slf4j:slf4j-simple:2.0.17")
}

kotlin { jvmToolchain(21) }

application { mainClass.set("vcit.eudi.MainKt") }
