plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

// 版本号跟发版流水线一致：默认 0.0.0，CI 传 -PcorplinkVersion=2026.11.22-3。
// versionCode 必须单调递增，直接取版本号里的全部数字：
// 2026.11.22 → 20261122，同日第二次 2026.11.22-3 → 202611223（仍在 int32 范围内）。
val corplinkVersion = (findProperty("corplinkVersion") as String?) ?: "0.0.0"
val corplinkVersionCode = corplinkVersion
    .filter { it.isDigit() }
    .toIntOrNull()
    ?.coerceAtLeast(1)
    ?: 1

android {
    namespace = "dev.corplink.android"
    compileSdk = 35

    defaultConfig {
        applicationId = "dev.corplink.android"
        minSdk = 24
        targetSdk = 35
        versionCode = corplinkVersionCode
        versionName = corplinkVersion
    }

    buildFeatures {
        compose = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    // gomobile bind 产物，构建方式见 apps/android/README.md。
    implementation(files("libs/corplink.aar"))
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation(platform("androidx.compose:compose-bom:2024.10.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
}
