# CFTester Proguard Rules
-keepattributes *Annotation*
-keepclassmembers class * {
    @org.json.* <methods>;
}
