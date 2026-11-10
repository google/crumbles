# R8 rules for release builds.

# The source code is public, so renaming classes and members would hide
# nothing and only make stack traces harder to read.
-dontobfuscate

# Strip every logging call, so that release builds write nothing to logcat.
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
    public static int i(...);
    public static int w(...);
    public static int e(...);
    public static int wtf(...);
    public static int println(...);
}
