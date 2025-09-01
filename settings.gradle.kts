// This block configures where Gradle looks for plugins.
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
    // This block defines the versions of the plugins used in the project.
    plugins {
        id("com.android.application") version "8.12.2" apply false
        id("org.jetbrains.kotlin.android") version "1.9.22" apply false
        id("com.google.protobuf") version "0.9.4" apply false
    }
}

// This block configures where Gradle looks for your app's library dependencies.
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "Crumbles"


