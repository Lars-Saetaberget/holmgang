# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}

# Uncomment this to preserve the line number information for
# debugging stack traces.
#-keepattributes SourceFile,LineNumberTable

# If you keep the line number information, uncomment this to
# hide the original source file name.
#-renamesourcefileattribute SourceFile

#-keepnames class org.mothra.smiley_day.NothingToSeeHereActivity {
#    !private <fields>;
#}

-keep class org.mothra.smiley_day.* {
    private void activateSecret();
    public static * RSA8092BitEncrypt(*);
    public static * RSA8092BitDecrypt(*);
    public static boolean isRunningOnCriminalCryptoPhone();
    public static boolean isRunningOnEmulator();
    public static double eval(*);
    public static * decryptStandardString(*);
    private static * runCommand(*);
    private static void setDebugMode(boolean);
}

-keepclassmembers class org.mothra.smiley_day.PasswordUtils {
    *;
}

-keep class **.R$string {
    *;
}

-dontshrink
-dontoptimize
#-optimizationpasses 1