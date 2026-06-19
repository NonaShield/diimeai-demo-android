package com.diimeai.demo.enrollment

/**
 * Observable state machine for device enrollment.
 *
 * Real-world lifecycle:
 *   App launch → [Pending] (enrollment running in background)
 *             → [Enrolled]  on success (button enabled, user can proceed)
 *             → [Failed]    on error  (error card shown, retry offered)
 *   Retry    → [Pending]   (re-enrollment starts)
 *
 * Emitted by [DiimeApp.enrollmentStatus] and collected by [MainActivity]
 * to gate the "Get Started" button and show error messages.
 */
sealed class EnrollmentStatus {

    /** Enrollment is running — no result yet. Button stays disabled. */
    object Pending : EnrollmentStatus()

    /**
     * Enrollment succeeded.
     * [deviceId] and [sessionId] are stored in EnrollmentState and ready for use
     * by PinningInterceptor on every subsequent API request.
     */
    data class Enrolled(
        val deviceId:  String,
        val sessionId: String
    ) : EnrollmentStatus()

    /**
     * Enrollment failed.
     * [reason]      — human-readable string safe to display (and log).
     * [isRetryable] — true for transient errors (network timeout, server 5xx).
     *                 false for hard failures (Play Integrity mandatory in PRODUCTION,
     *                 rooted device blocked, etc.) where retrying won't help.
     */
    data class Failed(
        val reason: String,
        val isRetryable: Boolean = true
    ) : EnrollmentStatus()
}
