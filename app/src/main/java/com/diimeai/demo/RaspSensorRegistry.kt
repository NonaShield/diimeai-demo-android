package com.diimeai.demo

/**
 * Canonical registry of every RASP sensor (signal class) registered by the SDK in
 * [com.payshield.sdk.PayShieldEdgeInitializer]. One row per `orchestrator.register(...)`
 * call — this is the source of truth for [ScenarioListFragment] tab 0 (Device / Runtime
 * Integrity), which renders this list as a live 3-column sensor status table.
 *
 * `signalTypes` lists every EdgeSignal `type` string a sensor can emit. A sensor's live
 * status is ACTIVE if `PayShieldEdgeInitializer.isSignalActive(type)` is true for ANY of
 * its types. `severity` is the worst-case severity across those types — the level shown
 * to the SOC/investor is always the highest risk that sensor is capable of flagging.
 *
 * Extracted directly from each signal class's `evaluate()` source — kept in sync manually
 * when a new signal is registered in PayShieldEdgeInitializer.
 */
object RaspSensorRegistry {

    enum class Severity(val label: String, val colorHex: String) {
        CRITICAL("Critical", "#FF2222"),
        HIGH("High", "#FF6600"),
        MEDIUM("Medium", "#FFAA00"),
        LOW("Low", "#FFDD55"),
    }

    data class Sensor(
        val name: String,
        val threatId: String,
        val severity: Severity,
        val signalTypes: List<String>,
    )

    val ALL: List<Sensor> = listOf(
        Sensor("Rogue Build Detected",        "RASP_DEV_035", Severity.CRITICAL, listOf("ROGUE_BUILD_DETECTED")),
        Sensor("Device Anchor Mismatch",       "RASP_DEV_036", Severity.HIGH,     listOf("DEVICE_ANCHOR_MISMATCH")),
        Sensor("ADB Install Detected",         "RASP_DEV_021", Severity.HIGH,     listOf("ADB_INSTALL")),
        Sensor("Root Cloaking Detected",       "RASP_DEV_023", Severity.HIGH,     listOf("ROOT_CLOAKING")),
        Sensor("Screen Mirroring Active",      "RASP_DEV_025", Severity.HIGH,     listOf("SCREEN_MIRRORING")),
        Sensor("SELinux Disabled",             "RASP_DEV_015", Severity.HIGH,     listOf("SELINUX_DISABLED")),
        Sensor("VPN Conflict Detected",        "RASP_DEV_024", Severity.MEDIUM,   listOf("VPN_CONFLICT")),
        Sensor("App Repackaged",               "RASP_DEV_022", Severity.CRITICAL, listOf("APP_REPACKAGED")),
        Sensor("Keyguard Not Secure",          "RASP_DEV_016", Severity.MEDIUM,   listOf("KEYGUARD_NOT_SECURE")),
        Sensor("User CA Certificate",          "RASP_DEV_020", Severity.HIGH,     listOf("USER_CA_CERT")),
        Sensor("Remote Desktop Active",        "RASP_DEV_026", Severity.HIGH,     listOf("REMOTE_DESKTOP")),
        Sensor("Hooking Framework",            "RASP_DEV_037", Severity.CRITICAL, listOf("HOOKING_FRAMEWORK")),
        Sensor("Ptrace Attached",              "RASP_DEV_038", Severity.CRITICAL, listOf("PTRACE_ATTACHED")),
        Sensor("Native Library Tamper",        "RASP_DEV_039", Severity.CRITICAL, listOf("NATIVE_LIB_TAMPER")),
        Sensor("Hardware Attestation Failure", "RASP_DEV_040", Severity.CRITICAL, listOf("ATTESTATION_NO_CHAIN", "ATTESTATION_UNTRUSTED")),
        Sensor("Untrusted IME Active",         "RASP_DEV_042", Severity.HIGH,     listOf("UNTRUSTED_IME")),
        Sensor("Emulator Fingerprint",         "RASP_DEV_046", Severity.HIGH,     listOf("EMULATOR_FINGERPRINT")),
        Sensor("SDK Self Tamper",              "RASP_DEV_047", Severity.CRITICAL, listOf("SDK_SELF_TAMPER")),
        Sensor("MASVS Control Failure",        "RASP_DEV_050", Severity.HIGH,     listOf("MASVS_CONTROL_FAILURE")),
        Sensor("Accessibility Abuse",          "USR_BEH_003",  Severity.CRITICAL, listOf("ACCESSIBILITY_GESTURE_INJECT", "ACCESSIBILITY_ABUSE")),
        Sensor("Screen Recording Active",      "RASP_DEV_051", Severity.HIGH,     listOf("SCREEN_RECORDING_ACTIVE", "COMPANION_SCREEN_SHARE_ACTIVE")),
        Sensor("App Clone Detected",           "RASP_DEV_055", Severity.CRITICAL, listOf("APP_CLONE_MALICIOUS", "APP_CLONE_DETECTED")),
        Sensor("Mock Location Detected",       "RASP_DEV_056", Severity.HIGH,     listOf("MOCK_LOCATION")),
        Sensor("SIM Swap Detected",            "RASP_DEV_052", Severity.CRITICAL, listOf("SIM_DEACTIVATED", "SIM_SWAP_DETECTED", "ESIM_OTA_SWAP", "ESIM_MANAGER_APP_DETECTED")),
        Sensor("Virtual Camera Detected",      "RASP_DEV_053", Severity.CRITICAL, listOf("VIRTUAL_CAMERA_DETECTED")),
        Sensor("Reverse Engineering Tool",     "RASP_DEV_060", Severity.CRITICAL, listOf("REFLECTION_PROTECTED_PACKAGE", "RE_TOOL_THREAD_DETECTED", "CLASS_COUNT_ANOMALY", "INJECTED_DEX_IN_PROC_MAPS")),
        Sensor("Shell Execution Detected",     "RASP_DEV_061", Severity.CRITICAL, listOf("SHELL_MAPPED_IN_PROCESS", "SHELL_CHILD_PROCESS_DETECTED", "DANGEROUS_EXECUTABLE_PRESENT")),
        Sensor("Content Provider Injection",   "RASP_DEV_062", Severity.CRITICAL, listOf("CONTENT_PROVIDER_SQL_INJECTION", "CONTENT_PROVIDER_NO_PERMISSION")),
        Sensor("High Risk Permissions",        "RASP_DEV_009", Severity.MEDIUM,   listOf("HIGH_RISK_PERMISSIONS")),
        Sensor("Concurrent Video Call",        "SCAM_DA_001",  Severity.HIGH,     listOf("CONCURRENT_VIDEO_CALL")),
        Sensor("Call Merge Detected",          "SCAM_CM_001",  Severity.HIGH,     listOf("CALL_MERGE_DETECTED")),
        Sensor("Enrollment Burst",             "BOT_APP_012",  Severity.HIGH,     listOf("ENROLLMENT_BURST")),
        Sensor("Sideload Detected",            "MAL_APK_001",  Severity.CRITICAL, listOf("SIDELOAD_DETECTED")),
        Sensor("Device Admin Abuse",           "MAL_APK_002",  Severity.CRITICAL, listOf("DEVICE_ADMIN_ABUSE")),
        Sensor("SMS Intercept Capable",        "MAL_APK_003",  Severity.CRITICAL, listOf("SMS_INTERCEPT_CAPABLE")),
        Sensor("NFC Relay / Fraud",            "NFC_FRAUD_003",Severity.CRITICAL, listOf("ROGUE_HCE_APP", "NFC_NO_KEYGUARD", "NFC_RELAY_DETECTED")),
        Sensor("Predatory Loan App",           "LOAN_APP_002", Severity.HIGH,     listOf("PREDATORY_LOAN_APP_FULL", "PREDATORY_LOAN_APP")),
        Sensor("Romance Social App",           "SCAM_RS_001",  Severity.LOW,      listOf("ROMANCE_SOCIAL_APP_INSTALLED")),
        Sensor("Overlay Attack Detected",      "RASP_DEV_063", Severity.CRITICAL, listOf("OVERLAY_ATTACK_DETECTED", "MANDATE_HIJACK_CAPABLE")),
        Sensor("Background Camera Active",     "RASP_DEV_064", Severity.HIGH,     listOf("BACKGROUND_CAMERA_ACTIVE")),
        Sensor("Deepfake Precondition",        "RASP_DEV_065", Severity.HIGH,     listOf("DEEPFAKE_PRECONDITION_DETECTED")),
        Sensor("Clipboard Scraping Risk",      "RASP_DEV_066", Severity.HIGH,     listOf("CLIPBOARD_SCRAPING_RISK")),
        Sensor("Local Storage Tampered",       "RASP_DEV_067", Severity.CRITICAL, listOf("LOCAL_STORAGE_TAMPERED")),
        Sensor("App Version Downgrade",        "RASP_DEV_068", Severity.CRITICAL, listOf("APP_VERSION_DOWNGRADE")),
        Sensor("Auto Clicker Detected",        "RASP_DEV_070", Severity.HIGH,     listOf("AUTO_CLICKER_DETECTED")),
        Sensor("USB Debugging Active",         "RASP_DEV_014", Severity.MEDIUM,   listOf("USB_DEBUGGING_ACTIVE", "DEVELOPER_OPTIONS_ACTIVE")),
        Sensor("Agentic Social Manipulation",  "SCAM_AI_002",  Severity.HIGH,     listOf("MESSAGING_APP_PRE_SESSION", "NOTIFICATION_TRIGGERED_SESSION")),
    )
}
