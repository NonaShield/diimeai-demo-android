package com.diimeai.demo

import android.os.Bundle
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.fragment.app.Fragment
import com.google.android.material.bottomnavigation.BottomNavigationView

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
    // This Activity does NOT wire touch capture itself. PayShieldEdgeInitializer
    // (registered once in DiimeApp) auto-attaches a BehavioralCaptureManager to
    // every Activity window that isn't already instrumented, wrapping
    // Window.Callback so it sees every touch regardless of what consumes it
    // (Button, EditText, etc. — a decor-view OnTouchListener would miss those).
    // That same automatic capture also feeds BehavioralBiometricsCollector
    // internally, which is what powers the "Behavioral & Biometric Fraud" tab's
    // live readout via PayShieldSDK.getBehaviourParams() below — and its sink
    // is the app-wide one already wired to both ThreatBuffer and the in-app
    // ticker, so signals reach the SOC dashboard too (the old local sink here
    // never did). See BehavioralCaptureManager / PayShieldEdgeInitializer for
    // the capture mechanism; nothing here needs to duplicate it.

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


