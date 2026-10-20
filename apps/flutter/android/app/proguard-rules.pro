# Antigravity Vault - Android ProGuard & R8 Optimization Rules

# Preserve Flutter Engine, JNI and Dart FFI bridge symbols
-keep class io.flutter.** { *; }
-keep class io.flutter.app.** { *; }
-keep class io.flutter.plugin.** { *; }
-keep class io.flutter.util.** { *; }
-keep class io.flutter.view.** { *; }
-keep class io.flutter.embedding.** { *; }

# Preserve Native Application and Autofill Service
-keep class com.antigravity.pwdvault.** { *; }
-keepclassmembers class com.antigravity.pwdvault.** { *; }

# Android Autofill Framework
-keep public class com.antigravity.pwdvault.pwdvault_flutter.PwdVaultAutofillService extends android.service.autofill.AutofillService {
    public <init>();
    public void onFillRequest(android.service.autofill.FillRequest, android.os.CancellationSignal, android.service.autofill.FillCallback);
    public void onSaveRequest(android.service.autofill.SaveRequest, android.service.autofill.SaveCallback);
}

# Android Biometrics and KeyStore StrongBox
-keep class androidx.biometric.** { *; }
-keep class androidx.fragment.app.FragmentActivity { *; }

# Keep native methods and classes for Rust FFI integration
-keepclasseswithmembernames class * {
    native <methods>;
}

# Serialization models
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}
