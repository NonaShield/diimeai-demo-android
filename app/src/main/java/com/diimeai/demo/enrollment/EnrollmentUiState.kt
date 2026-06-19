package com.diimeai.demo.enrollment

/**
 * Pure data class — no Android dependencies — that maps an [EnrollmentStatus]
 * to the exact booleans/strings that [MainActivity] uses to drive the UI.
 *
 * Keeping the mapping here (not inside the Activity) makes it trivially testable
 * with plain JUnit4: no Robolectric, no emulator, no Android runtime needed.
 */
data class EnrollmentUiState(
    /** Whether the "Get Started" button is clickable. */
    val buttonEnabled: Boolean,
    /** Label on the "Get Started" button. */
    val buttonLabel: String,
    /** Whether the spinning progress indicator below the button is shown. */
    val showProgress: Boolean,
    /** Whether the error card is visible. */
    val errorVisible: Boolean,
    /** Message shown in the error card; null when [errorVisible] is false. */
    val errorMessage: String?,
    /** Whether the "Retry" button inside the error card is visible. */
    val retryVisible: Boolean
) {
    companion object {
        fun from(status: EnrollmentStatus): EnrollmentUiState = when (status) {
            is EnrollmentStatus.Pending  -> EnrollmentUiState(
                buttonEnabled = false,
                buttonLabel   = "Setting up secure identity…",
                showProgress  = true,
                errorVisible  = false,
                errorMessage  = null,
                retryVisible  = false
            )
            is EnrollmentStatus.Enrolled -> EnrollmentUiState(
                buttonEnabled = true,
                buttonLabel   = "Get Started →",
                showProgress  = false,
                errorVisible  = false,
                errorMessage  = null,
                retryVisible  = false
            )
            is EnrollmentStatus.Failed   -> EnrollmentUiState(
                buttonEnabled = false,
                buttonLabel   = "Get Started",
                showProgress  = false,
                errorVisible  = true,
                errorMessage  = status.reason,
                retryVisible  = status.isRetryable
            )
        }
    }
}
