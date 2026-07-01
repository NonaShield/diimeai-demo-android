package com.diimeai.demo

/**
 * 40-parameter Behavioural Biometrics baseline vs. actual comparison for Tab 2.
 *
 * Baseline: enrolled from 15 minutes of normal mobile use (phone held in hand,
 * activity not necessarily continuous — typing, scrolling, tapping across the app).
 * Actual: current session reading.
 *
 * Status thresholds:
 *   MATCH   — within normal variance of enrolled baseline
 *   DRIFT   — measurable deviation, may indicate unfamiliar context or distraction
 *   ANOMALY — significant departure; contributes to X-Edge-Risk-Level behaviour score
 */
object BehaviourBiometricsRegistry {

    enum class Status(val symbol: String, val label: String, val colorHex: String) {
        MATCH("✓", "Match",   "#00CC55"),
        DRIFT("⚠", "Drift",   "#FFAA00"),
        ANOMALY("✗", "Anomaly","#FF3333"),
    }

    enum class Category(val label: String, val colorHex: String) {
        TOUCH("Touch & Tap",         "#4FC3F7"),
        KEYSTROKE("Keystroke",       "#CE93D8"),
        MOTION("Device Motion",      "#80CBC4"),
        SESSION("Session Behaviour", "#FFCC80"),
        CONTEXT("Environment",       "#A5D6A7"),
    }

    data class Param(
        val name:     String,
        val category: Category,
        val baseline: String,   // enrolled 15-min value
        val actual:   String,   // current session value
        val status:   Status,
    )

    val ALL: List<Param> = listOf(

        // ── Touch & Tap (1–10) ──────────────────────────────────────────────────
        Param("Touch Pressure",      Category.TOUCH,     "0.42 N",       "0.44 N",       Status.MATCH),
        Param("Contact Area",        Category.TOUCH,     "68 mm²",       "71 mm²",       Status.MATCH),
        Param("Tap Duration",        Category.TOUCH,     "124 ms",       "119 ms",       Status.MATCH),
        Param("Swipe Velocity",      Category.TOUCH,     "847 px/s",     "912 px/s",     Status.MATCH),
        Param("Swipe Linearity",     Category.TOUCH,     "94%",          "92%",          Status.MATCH),
        Param("Tap Interval",        Category.TOUCH,     "380 ms",       "395 ms",       Status.MATCH),
        Param("Pinch Speed",         Category.TOUCH,     "312 px/s",     "298 px/s",     Status.MATCH),
        Param("Scroll Acceleration", Category.TOUCH,     "2840 px/s²",   "2760 px/s²",   Status.MATCH),
        Param("Touch X Variance",    Category.TOUCH,     "±12 px",       "±14 px",       Status.MATCH),
        Param("Touch Y Variance",    Category.TOUCH,     "±9 px",        "±11 px",       Status.MATCH),

        // ── Keystroke Dynamics (11–16) ──────────────────────────────────────────
        Param("Key Dwell Time",      Category.KEYSTROKE, "98 ms",        "103 ms",       Status.MATCH),
        Param("Key Flight Time",     Category.KEYSTROKE, "143 ms",       "156 ms",       Status.MATCH),
        Param("Typing Speed",        Category.KEYSTROKE, "42 WPM",       "39 WPM",       Status.MATCH),
        Param("Error Rate",          Category.KEYSTROKE, "4.2%",         "5.1%",         Status.MATCH),
        Param("Backspace Frequency", Category.KEYSTROKE, "0.8 /min",     "1.3 /min",     Status.DRIFT),
        Param("Auto-correct Use",    Category.KEYSTROKE, "22%",          "34%",          Status.DRIFT),

        // ── Device Motion & Hold (17–26) ────────────────────────────────────────
        Param("Hold Tilt (Pitch)",   Category.MOTION,    "72°",          "69°",          Status.MATCH),
        Param("Hand Roll",           Category.MOTION,    "3.2°",         "3.8°",         Status.MATCH),
        Param("Grip Yaw",            Category.MOTION,    "1.8°",         "2.1°",         Status.MATCH),
        Param("Accelerometer RMS",   Category.MOTION,    "0.18 m/s²",   "0.21 m/s²",   Status.MATCH),
        Param("Gyro Stability",      Category.MOTION,    "0.04 rad/s",   "0.05 rad/s",   Status.MATCH),
        Param("Hand Tremor Freq",    Category.MOTION,    "9.2 Hz",       "9.5 Hz",       Status.MATCH),
        Param("Micro-movement",      Category.MOTION,    "0.6 mm",       "0.7 mm",       Status.MATCH),
        Param("Walk Cadence",        Category.MOTION,    "0 spm",        "0 spm",        Status.MATCH),
        Param("Jerk Index",          Category.MOTION,    "0.23 m/s³",    "0.25 m/s³",    Status.MATCH),
        Param("Portrait Stability",  Category.MOTION,    "98%",          "97%",          Status.MATCH),

        // ── Session Behaviour (27–35) ────────────────────────────────────────────
        Param("Page View Duration",  Category.SESSION,   "4.2 s",        "2.6 s",        Status.DRIFT),
        Param("Navigation Entropy",  Category.SESSION,   "1.8 bits",     "1.6 bits",     Status.MATCH),
        Param("Back-tap Rate",       Category.SESSION,   "0.3 /min",     "0.4 /min",     Status.MATCH),
        Param("Idle Gap",            Category.SESSION,   "2.1 s",        "1.7 s",        Status.MATCH),
        Param("Clipboard Use",       Category.SESSION,   "0.1 /session", "1.6 /session", Status.ANOMALY),
        Param("App Switch Rate",     Category.SESSION,   "0.4 /min",     "2.1 /min",     Status.ANOMALY),
        Param("Scroll Depth",        Category.SESSION,   "68%",          "72%",          Status.MATCH),
        Param("Copy-Paste Ratio",    Category.SESSION,   "8%",           "11%",          Status.MATCH),
        Param("Session Hour",        Category.SESSION,   "09:00–22:00",  "Within range", Status.MATCH),

        // ── Environmental Context (36–40) ────────────────────────────────────────
        Param("Network SSID",        Category.CONTEXT,   "Consistent",   "Consistent",   Status.MATCH),
        Param("Location Variance",   Category.CONTEXT,   "< 50 m",       "< 50 m",       Status.MATCH),
        Param("Ambient Light",       Category.CONTEXT,   "320 lux",      "285 lux",      Status.MATCH),
        Param("Battery Drain Rate",  Category.CONTEXT,   "1.2%/hr",      "1.4%/hr",      Status.MATCH),
        Param("Time-of-Day Pattern", Category.CONTEXT,   "Within window","Within window", Status.MATCH),
    )

    val matchCount:   Int get() = ALL.count { it.status == Status.MATCH }
    val driftCount:   Int get() = ALL.count { it.status == Status.DRIFT }
    val anomalyCount: Int get() = ALL.count { it.status == Status.ANOMALY }
}
