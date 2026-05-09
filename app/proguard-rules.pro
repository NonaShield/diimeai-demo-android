# DiimeAI Demo — ProGuard rules
# NonaShield SDK has its own consumer-proguard-rules.pro — nothing extra needed.

# Keep OkHttp (referenced by PinningInterceptor)
-keep class okhttp3.** { *; }
-dontwarn okhttp3.**

# Keep Kotlin coroutines
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}

# Keep BuildConfig fields referenced in code
-keep class com.diimeai.demo.BuildConfig { *; }
