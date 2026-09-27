plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.serialization")
}

android {
    namespace = "com.cftester.scanner"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.cftester.scanner"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "1.0.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        vectorDrawables {
            useSupportLibrary = true
        }

        ndk {
            abiFilters += setOf("arm64-v8a", "x86_64")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        debug {
            applicationIdSuffix = ".debug"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
        freeCompilerArgs += listOf(
            "-opt-in=kotlinx.coroutines.ExperimentalCoroutinesApi",
            "-opt-in=androidx.compose.material3.ExperimentalMaterial3Api"
        )
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.14"
    }

    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}

// =========================================================================
// Xray-core Android Binary Bundling (RealDelay & W^X Compliance)
// =========================================================================
tasks.register("downloadXrayBinaries") {
    group = "build"
    description = "Downloads and bundles Xray-core Android binaries (libxray.so) into jniLibs"

    val jniDir = file("src/main/jniLibs")
    val arm64So = File(jniDir, "arm64-v8a/libxray.so")
    val x86_64So = File(jniDir, "x86_64/libxray.so")

    outputs.files(arm64So, x86_64So)

    doLast {
        if (arm64So.exists() && x86_64So.exists() && arm64So.length() > 0 && x86_64So.length() > 0) {
            logger.lifecycle("Xray binaries already present in jniLibs (${arm64So.length()} / ${x86_64So.length()} bytes).")
            return@doLast
        }

        val rootDir = project.rootDir.parentFile ?: project.rootDir
        val scriptFile = File(rootDir, "scripts/download_xray_android.py")
        if (!scriptFile.exists()) {
            logger.warn("Warning: download_xray_android.py script not found at ${scriptFile.absolutePath}")
            return@doLast
        }

        val isWindows = System.getProperty("os.name").lowercase().contains("windows")
        val pythonCmd = if (isWindows) "python" else "python3"

        logger.lifecycle("Executing Xray binary download script: ${scriptFile.absolutePath}...")
        try {
            project.exec {
                workingDir = rootDir
                commandLine(
                    pythonCmd,
                    scriptFile.absolutePath,
                    "--output-dir",
                    jniDir.absolutePath,
                    "--offline-fallback"
                )
                isIgnoreExitValue = false
            }
        } catch (e: Exception) {
            logger.warn("Warning: Could not execute download_xray_android.py (${e.message}). Proceeding with existing assets.")
        }
    }
}

tasks.matching { it.name == "preBuild" }.configureEach {
    dependsOn("downloadXrayBinaries")
}

dependencies {
    // AndroidX Core & Lifecycle
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.0")
    implementation("androidx.activity:activity-compose:1.9.0")

    // Jetpack Compose
    val composeBom = platform("androidx.compose:compose-bom:2024.05.00")
    implementation(composeBom)
    androidTestImplementation(composeBom)
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")

    // Kotlin Coroutines
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")

    // Serialization & JSON
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.3")
    implementation("com.google.code.gson:gson:2.10.1")

    // Networking (BGP Fetcher & RealDelay proxy validation)
    implementation("com.squareup.okhttp3:okhttp:4.12.0")

    // Testing
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.8.1")
    testImplementation("org.json:json:20240303")
    testImplementation("androidx.test:core:1.5.0")
    testImplementation("androidx.test.ext:junit:1.1.5")
    debugImplementation("androidx.compose.ui:ui-tooling")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
}
