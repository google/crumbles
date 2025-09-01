// build.gradle.kts for the Crumbles application (single-module setup)

// 1. PLUGINS
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("com.google.protobuf")
}

// 2. ANDROID CONFIGURATION
android {
    namespace = "com.android.securelogging"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.android.securelogging"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
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

// 3. PROTOBUF CONFIGURATION
protobuf {
    protoc {
        artifact = "com.google.protobuf:protoc:3.25.3"
    }
    generateProtoTasks {
        all().forEach { task ->
            task.builtins.create("java") {
                option("lite")
            }
        }
    }
}

// 4. DEPENDENCIES
dependencies {
    // Protobuf Dependencies
    implementation("com.google.protobuf:protobuf-javalite:3.25.3")
    implementation("com.google.protobuf:protobuf-java-util:3.25.3") {
        // Exclude the full protobuf-java runtime to avoid conflicts with the lite runtime.
        exclude(group = "com.google.protobuf", module = "protobuf-java")
    }

    // AndroidX Libraries
    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation("androidx.biometric:biometric:1.2.0-alpha05")
    implementation("androidx.camera:camera-camera2:1.3.1")
    implementation("androidx.camera:camera-core:1.3.1")
    implementation("androidx.camera:camera-lifecycle:1.3.1")
    implementation("androidx.camera:camera-view:1.3.1")
    implementation("androidx.constraintlayout:constraintlayout:2.1.4")
    implementation("androidx.core:core:1.12.0")
    implementation("androidx.fragment:fragment:1.6.2")
    implementation("androidx.lifecycle:lifecycle-common:2.6.2")
    implementation("androidx.lifecycle:lifecycle-runtime:2.6.2")
    implementation("androidx.navigation:navigation-runtime:2.7.6")
    implementation("androidx.recyclerview:recyclerview:1.3.2")
    implementation("androidx.work:work-runtime:2.9.0")
    implementation("androidx.annotation:annotation:1.7.1")

    // Google Libraries
    implementation("com.google.android.gms:play-services-tasks:18.1.0")
    implementation("com.google.android.material:material:1.11.0")
    implementation("com.google.errorprone:error_prone_annotations:2.23.0")
    implementation("com.google.guava:guava:33.0.0-android")
    implementation("com.google.mlkit:barcode-scanning:17.2.0")
    implementation("com.google.mlkit:common:18.10.0")
    implementation("com.google.zxing:core:3.5.3")


    // Other Third-Party Libraries
    implementation("javax.annotation:jsr250-api:1.0")

    // Testing Dependencies
    testImplementation("junit:junit:4.13.2")
    testImplementation("androidx.test:core:1.5.0")
    testImplementation("androidx.test.ext:junit:1.1.5")
    testImplementation("androidx.work:work-testing:2.9.0")
    testImplementation("androidx.fragment:fragment-testing:1.6.2")
    testImplementation("com.google.truth:truth:1.4.0")
    testImplementation("org.mockito:mockito-core:5.10.0")
    testImplementation("org.robolectric:robolectric:4.11.1")
    testImplementation("org.robolectric:shadows-framework:4.11.1")
    testImplementation("androidx.test:monitor:1.6.1")
}


