plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.bitaid.app"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.bitaid.app"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.4.0-signet"

        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    // Google Tink (Apache-2.0): hardware-backed Android Keystore master key + AES256-GCM AEAD
    implementation("com.google.crypto.tink:tink-android:1.15.0")
}
