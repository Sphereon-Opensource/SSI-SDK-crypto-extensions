plugins {
    id("com.android.library")
    kotlin("android")
}

android {
    namespace = "com.sphereon.musap.shared"
    compileSdk = 34

    defaultConfig {
        minSdk = 26
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets {
        named("main") {
            java.srcDirs("src/androidMain/kotlin")
            kotlin.srcDirs("src/androidMain/kotlin")
        }
    }
}

dependencies {
    implementation("com.facebook.react:react-android")
    implementation("fi.methics.musap:musap-android:1.0.0") {
        exclude(group = "com.yubico.yubikit", module = "core")
        exclude(group = "com.yubico.yubikit", module = "android")
        exclude(group = "com.yubico.yubikit", module = "piv")
    }
    implementation("com.nimbusds:nimbus-jose-jwt:9.40")
    // implementation(files("libs/nimbus-jose-jwt-9.21.jar"))
}

repositories {
    mavenCentral()
    // Add other repositories if needed
}
