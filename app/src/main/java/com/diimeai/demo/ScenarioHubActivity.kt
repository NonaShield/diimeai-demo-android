package com.diimeai.demo

import android.os.Bundle
import android.view.MotionEvent
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.fragment.app.Fragment
import com.google.android.material.bottomnavigation.BottomNavigationView
import com.payshield.sdk.PayShieldEdgeInitializer

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

    override fun dispatchTouchEvent(ev: MotionEvent): Boolean {
        PayShieldEdgeInitializer.recordTouchForBiometrics(ev)
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
