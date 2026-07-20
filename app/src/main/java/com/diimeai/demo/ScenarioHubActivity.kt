package com.diimeai.demo

import android.os.Bundle
import android.view.MotionEvent
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.fragment.app.Fragment
import com.diimeai.demo.network.DiimeApiClient
import com.google.android.material.bottomnavigation.BottomNavigationView
import com.payshield.sdk.PayShieldSDK
import com.payshield.sdk.behavioral.BehavioralCaptureManager
import com.payshield.sdk.signal.EdgeSignal
import com.payshield.sdk.token.SessionHolder

/**
 * Main hub after login — 5-tab fraud scenario dashboard.
 *
 * Tab → Category mapping:
 *   0. Device / Runtime Integrity (RASP)
 *   1. Identity & Account Fraud
 *   2. Behavioral & Biometric Fraud
 *   3. Network / Transaction Fraud
 *   4. Compliance (live cryptographic compliance from backend telemetry)
 *
 * Tabs 0-3 use [ScenarioListFragment]; tab 4 uses [ComplianceFragment].
 * Fragments are created once and shown/hidden to preserve scroll position.
 */
class ScenarioHubActivity : AppCompatActivity() {

    companion object {
        private val TAB_TITLES = listOf(
            "Device / Runtime Integrity (RASP)",
            "Identity & Account Fraud",
            "Behavioral & Biometric Fraud",
            "Network / Transaction Fraud",
            "Compliance",
        )

        private val TAB_MENU_IDS = listOf(
            R.id.tab_device_rasp,
            R.id.tab_identity,
            R.id.tab_behavioral,
            R.id.tab_network,
            R.id.tab_platform,
        )
    }

    private lateinit var bottomNav: BottomNavigationView
    private lateinit var tvCategoryTitle: TextView

    // Fragments cached after first creation so scroll position is preserved
    private val fragmentCache = mutableMapOf<Int, Fragment>()
    private var activeTabIndex = 0

    // ── Behavioral SDK ────────────────────────────────────────────────────────
    //
    // PayShieldSDK.recordTouchForBiometrics() below feeds BehavioralBiometricsCollector,
    // which only powers the on-device "live biometric readout" demo screen
    // (PayShieldSDK.getBehaviourParams()) -- it is a separate object from
    // BehavioralCaptureManager and never touches BackendUploader.latestBehavioralFeatures,
    // so none of it ever reaches ThreatBuffer/SOC dashboard.
    //
    // BehavioralCaptureManager is the component PayShieldCheckpoint.evaluate()'s
    // "Path A: behavioral" line actually reads (via its latestSessionFeatures
    // companion property) before every /threats/batch upload -- same class
    // LoginActivity already uses. Feeding it here directly from
    // dispatchTouchEvent(), rather than via BehavioralCaptureManager.attachTo()'s
    // View.OnTouchListener, is deliberate: a ViewGroup's OnTouchListener is not
    // reliably invoked for touches a child view (Button, EditText) itself
    // consumes, which is most interaction in this hub. dispatchTouchEvent() sees
    // every touch before any child view processes it, so nothing is missed.
    private val behavioralSink = object : com.payshield.sdk.signal.SignalSink {
        override fun emit(signal: EdgeSignal) {
            DiimeApiClient.signalSink?.onSignalsCollected(listOf(signal))
        }
        override fun onBlock(reason: String) {
            DiimeApiClient.signalSink?.onBlock(reason)
        }
    }

    private val captureManager by lazy {
        BehavioralCaptureManager(
            sink      = behavioralSink,
            sessionId = SessionHolder.session?.sessionId ?: "hub_${System.currentTimeMillis()}",
        )
    }

    override fun dispatchTouchEvent(ev: MotionEvent): Boolean {
        PayShieldSDK.recordTouchForBiometrics(ev)
        captureManager.onTouch(window.decorView, ev)
        return super.dispatchTouchEvent(ev)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_scenario_hub)

        bottomNav       = findViewById(R.id.bottomNav)
        tvCategoryTitle = findViewById(R.id.tvCategoryTitle)

        // Show first tab immediately (no savedInstanceState check needed for demo)
        showTab(0)

        bottomNav.setOnItemSelectedListener { item ->
            val idx = TAB_MENU_IDS.indexOf(item.itemId)
            if (idx >= 0 && idx != activeTabIndex) showTab(idx)
            true
        }
    }

    private fun showTab(tabIndex: Int) {
        activeTabIndex = tabIndex
        tvCategoryTitle.text = TAB_TITLES[tabIndex]

        val fragment = fragmentCache.getOrPut(tabIndex) {
            if (tabIndex == 4) ComplianceFragment.newInstance()
            else ScenarioListFragment.newInstance(tabIndex)
        }

        val tx = supportFragmentManager.beginTransaction()

        // Hide all cached fragments
        fragmentCache.values.forEach { f ->
            if (f.isAdded && f !== fragment) tx.hide(f)
        }

        // Show or add the selected fragment
        if (fragment.isAdded) {
            tx.show(fragment)
        } else {
            tx.add(R.id.hubFragmentContainer, fragment, "tab_$tabIndex")
        }

        tx.commit()
    }
}


