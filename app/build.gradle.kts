plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

val PEPENET_APP_VERSION = "0.0.1"

android {
    namespace = "com.example.pepenet"
    compileSdk {
        version = release(37)
    }

    defaultConfig {
        applicationId = "com.example.pepenet"
        // 29: VpnService.Builder.setHttpProxy — how browsers are steered to the DANE proxy
        minSdk = 29
        targetSdk = 37
        versionCode = 1
        versionName = PEPENET_APP_VERSION

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        ndk {
            // prebuilt OpenSSL 3 ships for these two: phones + the x86_64 emulator
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    // The canonical PepeNet C stack (chain sync, .pepe resolver, DANE proxy).
    // Needs the NDK + CMake — Android Studio installs them on first sync.
    externalNativeBuild {
        cmake {
            path = file("../native/CMakeLists.txt")
        }
    }

    buildTypes {
        release {
            optimization {
                enable = false
            }
            // 0.0.1 is side-loaded from GitHub, so sign it with the debug key to
            // keep it installable without a keystore. Swap in a real signingConfig
            // before any store release.
            signingConfig = signingConfigs.getByName("debug")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    buildFeatures {
        compose = true
    }
    lint {
        // don't let lint-vital block the side-loaded 0.0.1 release build
        checkReleaseBuilds = false
    }
}

dependencies {
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.kotlinx.coroutines.android)
    testImplementation(libs.junit)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.runner)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
    debugImplementation(libs.androidx.compose.ui.tooling)
}

// Copies the signed release APK to releases/PepeNet-<version>.apk (the file
// linked from the README). Run: ./gradlew :app:publishApk
val publishedApkName = "PepeNet-$PEPENET_APP_VERSION.apk"
tasks.register<Copy>("publishApk") {
    val apkName = publishedApkName
    dependsOn("assembleRelease")
    // AGP 9 writes the signed APK under intermediates/; older versions under outputs/
    from(layout.buildDirectory.dir("outputs/apk/release"), layout.buildDirectory.dir("intermediates/apk/release"))
    include("app-release.apk")
    rename { apkName }
    into(rootProject.layout.projectDirectory.dir("releases"))
}
// one-off: an IDE build also produces the downloadable APK
tasks.matching { it.name == "assembleDebug" }.configureEach { finalizedBy("publishApk") }
