plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.example.vciclient"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.example.vciclient"
        minSdk = 26
        targetSdk = 33
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        vectorDrawables {
            useSupportLibrary = true
        }

        manifestPlaceholders["appAuthRedirectScheme"] = "com.example.vci-client.demo"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    kotlinOptions {
        jvmTarget = "1.8"
    }
    buildFeatures {
        compose = true
    }
    composeOptions {
        // Fix: Upgrade compiler to match Kotlin stdlib versions required by transitive dependencies (Tink/Nimbus).
        kotlinCompilerExtensionVersion = "1.5.11"
    }
    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
            pickFirsts += "META-INF/{LICENSE,LICENSE.txt,license.txt,NOTICE,NOTICE.txt,notice.txt,DEPENDENCIES,ASL2.0}"
            pickFirsts += "META-INF/INDEX.LIST"
            pickFirsts += "META-INF/io.netty.versions.properties"
        }
    }
}

dependencies {

    implementation("androidx.core:core-ktx:1.9.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.7.0")
    implementation("androidx.activity:activity-compose:1.8.2")
    implementation(platform("androidx.compose:compose-bom:2023.03.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-ktx:1.8.2")
    implementation("com.google.code.gson:gson:2.10.1")
    implementation("androidx.fragment:fragment-ktx:1.6.2")
    // Fix: Force 'android' variant to prevent crashes caused by transitive 'jre' variant (from Tink).
    implementation("com.google.guava:guava:31.1-android")


//INJI VCI client project
    implementation(project(":vci-client"))

    implementation("com.madgag.spongycastle:core:1.56.0.0")
    implementation("com.madgag.spongycastle:prov:1.56.0.0")
    implementation("com.madgag.spongycastle:bcpkix-jdk15on:1.56.0.0")
    implementation("net.openid:appauth:0.11.1")
    implementation("com.nimbusds:nimbus-jose-jwt:9.38-rc5")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.7.3")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("com.google.crypto.tink:tink-android:1.11.0")
    implementation ("androidx.camera:camera-camera2:1.3.0")
    implementation ("androidx.camera:camera-lifecycle:1.3.0")
    implementation ("androidx.camera:camera-view:1.3.0")
    implementation ("com.google.mlkit:barcode-scanning:17.2.0")
    implementation ("androidx.lifecycle:lifecycle-runtime-ktx:2.6.2")
    implementation ("com.google.accompanist:accompanist-permissions:0.32.0")




    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.1.5")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.5.1")
    androidTestImplementation(platform("androidx.compose:compose-bom:2023.03.00"))
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    debugImplementation("androidx.compose.ui:ui-tooling")
    debugImplementation("androidx.compose.ui:ui-test-manifest")

    // Fix: Prevent duplicate classes by strictly replacing legacy 'jdk15on' with modern 'jdk15to18'.
    modules {
        module("org.bouncycastle:bcprov-jdk15on") {
            replacedBy("org.bouncycastle:bcprov-jdk15to18", "Prevent class duplication")
        }
    }
}

configurations.all {
    exclude(group = "com.apicatalog", module = "titanium-json-ld")
    exclude(group = "com.google.protobuf", module = "protobuf-java")
    exclude(group = "com.google.crypto.tink", module = "tink")
}