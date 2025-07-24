plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("maven-publish")
    id("org.jetbrains.dokka") version "1.9.20"
    id("signing")

    jacoco
    id("org.sonarqube") version "5.1.0.4872"
}

jacoco {
    toolVersion = "0.8.11"
    reportsDirectory = layout.buildDirectory.dir("reports/jacoco")
}

android {
    namespace = "com.example.vciclient"
    compileSdk = 34

    defaultConfig {
        minSdk = 23

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
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
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    testOptions {
        unitTests {
            isReturnDefaultValues = true
        }
    }
}
dependencies {
    implementation("androidx.core:core-ktx:1.9.0")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("com.nimbusds:nimbus-jose-jwt:9.37.3")
    implementation("io.fusionauth:fusionauth-jwt:5.3.2")
    implementation("com.google.code.gson:gson:2.10.1")

    testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")
    testImplementation("io.mockk:mockk:1.13.10")
    testImplementation("org.junit.jupiter:junit-jupiter-api:5.10.2")
    testImplementation("org.json:json:20231013")
    androidTestImplementation("androidx.test.ext:junit:1.1.5")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.5.1")
}

tasks {
    register<JacocoReport>("jacocoTestReport") {
        dependsOn(
            listOf(
                "testDebugUnitTest",
                "compileReleaseUnitTestKotlin",
                "testReleaseUnitTest"
            )
        )

        reports {
            html.required = true
            xml.required = true
        }
        sourceDirectories.setFrom(layout.projectDirectory.dir("src/main/java"))
        classDirectories.setFrom(
            files(
                fileTree(layout.buildDirectory.dir("intermediates/javac/debug")),
                fileTree(layout.buildDirectory.dir("tmp/kotlin-classes/debug"))
            )
        )
        executionData.setFrom(files(
            fileTree(layout.buildDirectory) { include(listOf("**/testDebug**.exec")) }
        ))

    }
}

tasks.register<Jar>("javadocJar") {
    dependsOn("dokkaJavadoc")
    archiveClassifier.set("javadoc")
    from(tasks.named("dokkaHtml").get().outputs.files)
}
tasks.register<Jar>("sourcesJar") {
    archiveClassifier.set("sources")
    from(android.sourceSets["main"].java.srcDirs)
}

tasks.build {
    finalizedBy("jacocoTestReport")
}

sonarqube {
    properties {
        property( "sonar.java.binaries", "build/intermediates/javac/debug")
        property( "sonar.language", "kotlin")
        property( "sonar.exclusions", "**/build/**, **/*.kt.generated, **/R.java, **/BuildConfig.java")
        property( "sonar.scm.disabled", "true")
        property( "sonar.coverage.jacoco.xmlReportPaths", "build/reports/jacoco/jacocoTestReport/jacocoTestReport.xml")
    }
}

tasks.withType<Jar>().configureEach {
    doLast {
        ant.withGroovyBuilder {
            "checksum"(
                "algorithm" to "md5",
                "file" to archiveFile.get().asFile
            )
            "checksum"(
                "algorithm" to "sha1",
                "file" to archiveFile.get().asFile
            )
        }
    }
}

apply {
    from("publish-artifact.gradle")
}