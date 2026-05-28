package com.diimeai.demo.security

import android.content.Context
import android.telephony.TelephonyManager
import androidx.core.content.edit
import java.security.MessageDigest

/**
 * DeviceSignalStore — on-device persistent signal store for live fraud detection.
 *
 * Stores two classes of signal fingerprint:
 *
 *   SIM Fingerprint (UC-08 SIM Swap):
 *     Captured at first KYC enrollment from TelephonyManager.simOperator (MCC+MNC).
 *     Compared at every payment initiation.
 *     If the fingerprint changes → SIM swap suspected → fire SCAM_SS_001 CRITICAL.
 *     Combined with behavioral biometric deviation → dual-signal confidence 1.00.
 *     No special Android permission required for simOperator.
 *
 *   Enrollment Count (UC-06 Mule Account):
 *     Incremented after every successful KYC submission on this device.
 *     Sent as device_account_degree in each KYC payload.
 *     Thresholds:
 *       1st enrollment → ALLOW (baseline)
 *       2nd enrollment → STEP_UP (mule risk elevated)
 *       3rd+ enrollment → BLOCK (probable mule node)
 *
 * Storage: plain SharedPreferences (no PII — values are derived fingerprints,
 * not Aadhaar/PAN/MSISDN). DPDP Act compliant.
 */
object DeviceSignalStore {

    private const val PREFS_NAME           = "payshield_signals"
    private const val KEY_SIM_FINGERPRINT  = "enrolled_sim_fingerprint"
    private const val KEY_ENROLL_COUNT     = "device_enrollment_count"
    private const val KEY_ENROLL_LAST_TS   = "device_enrollment_last_ts"
    private const val KEY_ENROLL_WINDOW_TS = "device_enrollment_window_start"

    // ── SIM fingerprint ───────────────────────────────────────────────────────

    /**
     * Derive a SIM fingerprint from TelephonyManager fields that need no runtime
     * permission: simOperator (MCC+MNC), simCountryIso, and phoneCount.
     *
     * The result is a SHA-256 prefix (first 12 hex chars) so it is safe to log.
     */
    fun readSimFingerprint(context: Context): String? {
        return try {
            val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
                ?: return null
            val simOperator   = tm.simOperator   ?: ""        // e.g. "40411"
            val simCountryIso = tm.simCountryIso ?: ""        // e.g. "in"
            // Build a stable fingerprint from the composite
            val raw = "$simOperator|$simCountryIso|${tm.phoneCount}"
            if (simOperator.isBlank()) null   // no SIM present
            else sha256hex(raw).take(12)
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Persist the SIM fingerprint captured at KYC enrollment.
     * Call once when [getEnrollmentCount] == 0.
     */
    fun storeEnrolledSimFingerprint(context: Context, fingerprint: String) {
        prefs(context).edit { putString(KEY_SIM_FINGERPRINT, fingerprint) }
    }

    /**
     * @return the fingerprint stored at enrollment, or null if not yet enrolled.
     */
    fun getEnrolledSimFingerprint(context: Context): String? =
        prefs(context).getString(KEY_SIM_FINGERPRINT, null)

    /**
     * Compare current SIM state against the enrolled fingerprint.
     *
     * @return true if a SIM swap is suspected (fingerprint changed), false if clean,
     *         null if we cannot determine (no enrolled fingerprint or no SIM now).
     */
    fun isSimSwapSuspected(context: Context): Boolean? {
        val enrolled = getEnrolledSimFingerprint(context) ?: return null
        val current  = readSimFingerprint(context) ?: return null
        return enrolled != current
    }

    // ── Enrollment count (mule account degree) ────────────────────────────────

    /**
     * Total number of KYC enrollments completed on this device.
     * Returns 0 before any enrollment.
     */
    fun getEnrollmentCount(context: Context): Int =
        prefs(context).getInt(KEY_ENROLL_COUNT, 0)

    /**
     * Increment enrollment count after a successful KYC.
     * @return the NEW count (post-increment).
     */
    fun incrementEnrollmentCount(context: Context): Int {
        val next = getEnrollmentCount(context) + 1
        val now  = System.currentTimeMillis()
        prefs(context).edit {
            putInt(KEY_ENROLL_COUNT, next)
            putLong(KEY_ENROLL_LAST_TS, now)
            if (next == 1) putLong(KEY_ENROLL_WINDOW_TS, now)  // start window on first enrollment
        }
        return next
    }

    /**
     * Elapsed seconds since the previous enrollment (for velocity calculation).
     * Returns Long.MAX_VALUE if this is the first enrollment.
     */
    fun secondsSinceLastEnrollment(context: Context): Long {
        val ts = prefs(context).getLong(KEY_ENROLL_LAST_TS, 0L)
        return if (ts == 0L) Long.MAX_VALUE
        else (System.currentTimeMillis() - ts) / 1000
    }

    /**
     * Elapsed seconds since the FIRST enrollment in this window.
     * Used for burst velocity: ≥3 enrollments within 60s → CRITICAL.
     */
    fun secondsSinceWindowStart(context: Context): Long {
        val ts = prefs(context).getLong(KEY_ENROLL_WINDOW_TS, 0L)
        return if (ts == 0L) Long.MAX_VALUE
        else (System.currentTimeMillis() - ts) / 1000
    }

    /**
     * Reset all signals — call on clean logout or fresh install.
     */
    fun reset(context: Context) {
        prefs(context).edit { clear() }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private fun prefs(context: Context) =
        context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    private fun sha256hex(input: String): String =
        MessageDigest.getInstance("SHA-256")
            .digest(input.toByteArray())
            .joinToString("") { "%02x".format(it) }
}
