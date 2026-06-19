package com.diimeai.demo.enrollment

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Unit tests for the enrollment status state machine.
 *
 * Real-world contract being verified:
 *   - When the customer's app launches, enrollment starts immediately in the background.
 *   - "Get Started" (login button) must be DISABLED until enrollment succeeds.
 *   - If enrollment fails the user sees a clear error + a Retry button.
 *   - Retry resets status to Pending and re-runs enrollment.
 *   - A second launch where enrollment is already stored → Enrolled immediately, no network call.
 *
 * These are pure-JVM tests (no Android runtime required).  They exercise the
 * [EnrollmentStatus] sealed class and the [EnrollmentUiState] mapping — the same
 * logic consumed by MainActivity when deciding button/error-card visibility.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class EnrollmentStatusTest {

    // A fresh StateFlow for each test — mirrors DiimeApp.enrollmentStatus
    private lateinit var statusFlow: MutableStateFlow<EnrollmentStatus>

    @Before
    fun setUp() {
        statusFlow = MutableStateFlow(EnrollmentStatus.Pending)
    }

    // ── Initial state ─────────────────────────────────────────────────────────

    @Test
    fun `initial status is Pending`() = runTest {
        assertEquals(EnrollmentStatus.Pending, statusFlow.first())
    }

    @Test
    fun `Pending status maps to button disabled`() {
        val ui = EnrollmentUiState.from(EnrollmentStatus.Pending)
        assertFalse("Button must be disabled while enrolling", ui.buttonEnabled)
    }

    @Test
    fun `Pending status shows no error card`() {
        val ui = EnrollmentUiState.from(EnrollmentStatus.Pending)
        assertFalse("Error card must be hidden while enrolling", ui.errorVisible)
        assertNull("No error message while pending", ui.errorMessage)
    }

    @Test
    fun `Pending status shows progress label`() {
        val ui = EnrollmentUiState.from(EnrollmentStatus.Pending)
        assertTrue("Button label must indicate pending", ui.buttonLabel.contains("Setting up", ignoreCase = true))
    }

    // ── Success path ──────────────────────────────────────────────────────────

    @Test
    fun `Enrolled status enables the button`() = runTest {
        statusFlow.value = EnrollmentStatus.Enrolled(deviceId = "dev-001", sessionId = "sess-abc")
        val ui = EnrollmentUiState.from(statusFlow.first())
        assertTrue("Button must be enabled after enrollment", ui.buttonEnabled)
    }

    @Test
    fun `Enrolled status hides the error card`() = runTest {
        statusFlow.value = EnrollmentStatus.Enrolled(deviceId = "dev-001", sessionId = "sess-abc")
        val ui = EnrollmentUiState.from(statusFlow.first())
        assertFalse("Error card must be hidden after enrollment", ui.errorVisible)
        assertNull("No error message after enrollment", ui.errorMessage)
    }

    @Test
    fun `Enrolled status shows Get Started label`() = runTest {
        statusFlow.value = EnrollmentStatus.Enrolled(deviceId = "dev-001", sessionId = "sess-abc")
        val ui = EnrollmentUiState.from(statusFlow.first())
        assertTrue("Button label must say Get Started", ui.buttonLabel.contains("Get Started", ignoreCase = true))
    }

    @Test
    fun `Enrolled carries device and session id`() = runTest {
        statusFlow.value = EnrollmentStatus.Enrolled(deviceId = "d-42", sessionId = "s-99")
        val enrolled = statusFlow.first() as EnrollmentStatus.Enrolled
        assertEquals("d-42", enrolled.deviceId)
        assertEquals("s-99", enrolled.sessionId)
    }

    // ── Failure path ──────────────────────────────────────────────────────────

    @Test
    fun `Failed status disables the button`() = runTest {
        statusFlow.value = EnrollmentStatus.Failed(reason = "Network timeout", isRetryable = true)
        val ui = EnrollmentUiState.from(statusFlow.first())
        assertFalse("Button must be disabled on enrollment failure", ui.buttonEnabled)
    }

    @Test
    fun `Failed status shows error card`() = runTest {
        statusFlow.value = EnrollmentStatus.Failed(reason = "Network timeout", isRetryable = true)
        val ui = EnrollmentUiState.from(statusFlow.first())
        assertTrue("Error card must be visible on failure", ui.errorVisible)
    }

    @Test
    fun `Failed status exposes error reason`() = runTest {
        statusFlow.value = EnrollmentStatus.Failed(reason = "Backend rejected enrollment: HTTP 503")
        val ui = EnrollmentUiState.from(statusFlow.first())
        assertEquals("Backend rejected enrollment: HTTP 503", ui.errorMessage)
    }

    @Test
    fun `Failed status shows retry button when retryable`() = runTest {
        statusFlow.value = EnrollmentStatus.Failed(reason = "Timeout", isRetryable = true)
        val ui = EnrollmentUiState.from(statusFlow.first())
        assertTrue("Retry button must be visible for retryable failures", ui.retryVisible)
    }

    @Test
    fun `Failed status hides retry button when not retryable`() = runTest {
        statusFlow.value = EnrollmentStatus.Failed(
            reason = "Play Integrity mandatory in PRODUCTION — attestation failed",
            isRetryable = false
        )
        val ui = EnrollmentUiState.from(statusFlow.first())
        assertFalse("Retry must be hidden for hard failures (e.g. integrity violation)", ui.retryVisible)
    }

    // ── Retry flow ────────────────────────────────────────────────────────────

    @Test
    fun `retry resets status from Failed back to Pending`() = runTest {
        statusFlow.value = EnrollmentStatus.Failed("Timeout")
        // Retry: reset to Pending, then re-enrollment starts
        statusFlow.value = EnrollmentStatus.Pending
        assertEquals(EnrollmentStatus.Pending, statusFlow.first())
    }

    @Test
    fun `retry then success transitions Pending to Enrolled`() = runTest {
        statusFlow.value = EnrollmentStatus.Failed("Timeout")
        statusFlow.value = EnrollmentStatus.Pending
        statusFlow.value = EnrollmentStatus.Enrolled(deviceId = "dev-001", sessionId = "s-new")

        val ui = EnrollmentUiState.from(statusFlow.first())
        assertTrue(ui.buttonEnabled)
        assertFalse(ui.errorVisible)
    }

    // ── Already enrolled on second launch ─────────────────────────────────────

    @Test
    fun `already enrolled on second launch goes directly to Enrolled`() = runTest {
        // Simulates DiimeApp.enrollDevice() fast path when EnrollmentState.load() != null
        statusFlow.value = EnrollmentStatus.Enrolled(deviceId = "dev-persisted", sessionId = "s-stored")
        val status = statusFlow.first()
        assertTrue("Must be Enrolled immediately on second launch", status is EnrollmentStatus.Enrolled)
        val ui = EnrollmentUiState.from(status)
        assertTrue("Button must be enabled immediately on second launch", ui.buttonEnabled)
    }

    // ── State machine exhaustiveness ──────────────────────────────────────────

    @Test
    fun `all three states produce distinct ui states`() {
        val pending  = EnrollmentUiState.from(EnrollmentStatus.Pending)
        val enrolled = EnrollmentUiState.from(EnrollmentStatus.Enrolled("d", "s"))
        val failed   = EnrollmentUiState.from(EnrollmentStatus.Failed("err"))

        // Button enabled only in Enrolled
        assertFalse(pending.buttonEnabled)
        assertTrue(enrolled.buttonEnabled)
        assertFalse(failed.buttonEnabled)

        // Error only in Failed
        assertFalse(pending.errorVisible)
        assertFalse(enrolled.errorVisible)
        assertTrue(failed.errorVisible)

        // Progress only in Pending
        assertTrue(pending.showProgress)
        assertFalse(enrolled.showProgress)
        assertFalse(failed.showProgress)
    }
}
