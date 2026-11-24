import java.net.URI
import java.nio.file.FileSystems
import java.nio.file.Files
import java.util.jar.JarEntry
import java.util.jar.JarOutputStream

plugins {
    id("com.android.application") version "8.7.3"
    id("com.google.protobuf") version "0.9.4"
}

android {
    namespace = "com.android.securelogging"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.android.securelogging"
        // The same as android:minSdkVersion in AndroidManifest.xml, which this value would override.
        minSdk = 34
        targetSdk = 35
        versionCode = 2
        versionName = "2.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
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
    buildFeatures {
        viewBinding = true
    }
    testOptions {
        unitTests {
            isIncludeAndroidResources = true
            all { test ->
                // Robolectric keeps the static state of the app between the test classes that share
                // a JVM, while each test class expects to start from a new app.
                test.forkEvery = 1
                // Only a few JVMs at a time, as the tests that move the clock past a transfer
                // deadline need the transfer thread to start waiting promptly.
                test.maxParallelForks =
                    (Runtime.getRuntime().availableProcessors() / 2).coerceIn(1, 4)
                if (test.name == "testDebugUnitTest") {
                    // Debug builds replace the network security config with
                    // src/debug/res/xml/network_security_config.xml, which permits cleartext to a
                    // WebDAV server on the device. The release unit tests check the config that
                    // release builds ship.
                    test.exclude("**/CrumblesNetworkSecurityConfigTest.class")
                }
            }
        }
    }
    sourceSets {
        getByName("main") {
            (this as org.gradle.api.plugins.ExtensionAware).extensions.configure<
                org.gradle.api.file.SourceDirectorySet
            >("proto") {
                srcDir("src/main")
                include("logs.proto", "user_key_prefs.proto")
            }
        }
    }
    dependenciesInfo {
        // AGP would otherwise add a block of dependency metadata, encrypted to a key of Google
        // Play, to the APK signing block, which nobody else can check against the build.
        includeInApk = false
        includeInBundle = false
    }
}

// Archives without file timestamps and with their entries in a fixed order, so that two builds of
// the same commit produce the same unsigned outputs (see RELEASING.md).
tasks.withType<AbstractArchiveTask>().configureEach {
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
}

// AGP compiles unit tests against the Android SDK system image, which omits the host JDK's
// jdk.httpserver module. Expose its classes only at unit-test compile time; at test runtime the
// JVM provides jdk.httpserver directly.
val generateJdkHttpServerStubs by tasks.registering {
    val outputJar = layout.buildDirectory.file("generated/jdk-httpserver-stubs/jdk-httpserver.jar")
    outputs.file(outputJar)
    doLast {
        val out = outputJar.get().asFile
        out.parentFile.mkdirs()
        val jrtFs = FileSystems.getFileSystem(URI.create("jrt:/"))
        val root = jrtFs.getPath("/modules/jdk.httpserver")
        JarOutputStream(out.outputStream().buffered()).use { jar ->
            Files.walk(root).use { paths ->
                paths.filter { path ->
                    Files.isRegularFile(path) &&
                        path.toString().endsWith(".class") &&
                        path.fileName.toString() != "module-info.class"
                }.forEach { classFile ->
                    val entryName = root.relativize(classFile).toString().replace('\\', '/')
                    jar.putNextEntry(JarEntry(entryName))
                    Files.copy(classFile, jar)
                    jar.closeEntry()
                }
            }
        }
    }
}

protobuf {
    protoc {
        artifact = "com.google.protobuf:protoc:3.25.5"
    }
    generateProtoTasks {
        all().forEach { task ->
            task.builtins {
                create("java") {
                    option("lite")
                }
            }
        }
    }
}

dependencies {
    implementation("androidx.annotation:annotation:1.9.1")
    // AppCompat 1.8 extends the decor action bar behind the status bar of edge-to-edge windows, as
    // on Android 15 and higher, which CrumblesWindowInsetsTest checks.
    implementation("androidx.appcompat:appcompat:1.8.0-rc01")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.constraintlayout:constraintlayout:2.2.0")
    implementation("androidx.core:core:1.15.0")
    implementation("androidx.fragment:fragment:1.8.5")
    implementation("androidx.lifecycle:lifecycle-common:2.8.7")
    implementation("androidx.lifecycle:lifecycle-livedata-core:2.8.7")
    implementation("androidx.recyclerview:recyclerview:1.3.2")
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.datastore:datastore:1.2.1")
    implementation("androidx.datastore:datastore-guava:1.2.1")
    implementation("androidx.work:work-runtime:2.10.0")
    implementation("androidx.documentfile:documentfile:1.0.1")
    implementation("androidx.camera:camera-core:1.4.1")
    implementation("androidx.camera:camera-camera2:1.4.1")
    implementation("androidx.camera:camera-lifecycle:1.4.1")
    implementation("androidx.camera:camera-view:1.4.1")
    implementation("com.google.errorprone:error_prone_annotations:2.36.0")
    implementation("com.google.zxing:core:3.5.3")
    implementation("com.google.guava:guava:33.3.1-android")
    implementation("com.google.protobuf:protobuf-javalite:3.25.5")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.robolectric:robolectric:4.17")
    testImplementation("com.google.truth:truth:1.4.4")
    testImplementation("org.mockito:mockito-core:5.14.2")
    testImplementation("androidx.test:core:1.6.1")
    testImplementation("androidx.test.ext:junit:1.2.1")
    testImplementation("androidx.fragment:fragment-testing:1.8.5")
    testImplementation("androidx.navigation:navigation-runtime:2.8.5")
    testImplementation("androidx.work:work-testing:2.10.0")
    testImplementation("com.google.code.findbugs:jsr305:3.0.2")
    testImplementation("com.google.testparameterinjector:test-parameter-injector:1.18")
    testImplementation("com.squareup.okhttp3:okhttp-tls:4.12.0")
    testCompileOnly(
        files(layout.buildDirectory.file("generated/jdk-httpserver-stubs/jdk-httpserver.jar")) {
            builtBy(generateJdkHttpServerStubs)
        }
    )
}
