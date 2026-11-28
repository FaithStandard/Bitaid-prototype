package com.bitaid.app

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.Typeface
import android.location.Location
import android.location.LocationListener
import android.location.LocationManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.CancellationSignal
import android.os.Handler
import android.os.Looper
import android.os.PowerManager
import android.provider.Settings
import android.text.InputType
import android.view.View
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import org.json.JSONArray
import java.util.concurrent.atomic.AtomicBoolean

/**
 * M4 Android shell around `bitaid-node` + `bitaid-tor`.
 *
 * - Separate Caller ("Ask for help") and Responder ("Help others") modes, selectable on first
 *   launch and switchable at any time.
 * - Plain-language labels and help lines on every field; technical checks, logs, and test-network
 *   knobs live behind collapsible sections.
 * - Masked RPC URL: once stored encrypted in Keystore, never repopulated into a plaintext EditText.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var callerTabBtn: Button
    private lateinit var responderTabBtn: Button

    private lateinit var statusView: TextView
    private lateinit var progressView: TextView
    private lateinit var warningBanner: TextView

    // Mode containers
    private lateinit var callerSection: LinearLayout
    private lateinit var responderSection: LinearLayout
    private lateinit var responderSettingsSection: LinearLayout

    // Caller controls
    private lateinit var callerStateHint: TextView
    private lateinit var prepareCallerBtn: Button
    private lateinit var sosBtn: Button
    private lateinit var cancelCallerBtn: Button

    // Responder controls
    private lateinit var dutySwitch: Switch
    private lateinit var batteryBtn: Button

    // Alert card
    private lateinit var alertCard: LinearLayout
    private lateinit var alertText: TextView
    private lateinit var alertDetailsBtn: Button
    private lateinit var alertDetailsText: TextView
    private lateinit var acceptBtn: Button
    private lateinit var declineBtn: Button

    // Verified Location card
    private lateinit var locCard: LinearLayout
    private lateinit var locText: TextView
    private lateinit var mapsBtn: Button

    // Ballot card
    private lateinit var ballotCard: LinearLayout
    private lateinit var ballotCountdownText: TextView
    private lateinit var ballotSeatsBox: LinearLayout
    private lateinit var achievedCheck: CheckBox
    private lateinit var misuseCheck: CheckBox
    private lateinit var voteBtn: Button

    // Connection settings (shared)
    private lateinit var nameEdit: EditText
    private lateinit var peerEdit: EditText
    private lateinit var coreKeyEdit: EditText
    private lateinit var tipSourcesEdit: EditText
    private lateinit var anchorEdit: EditText

    // Wallet settings (Responder)
    private lateinit var rpcStatusView: TextView
    private lateinit var rpcReplaceBtn: Button
    private lateinit var rpcInputRow: LinearLayout
    private lateinit var rpcEdit: EditText
    private lateinit var rpcShowCheck: CheckBox
    private lateinit var rpcSaveBtn: Button
    private lateinit var walletEdit: EditText

    // Advanced / Test network (collapsible)
    private lateinit var advancedToggleBtn: Button
    private lateinit var advancedSection: LinearLayout
    private lateinit var poolEdit: EditText
    private lateinit var satScaleEdit: EditText
    private lateinit var timeScaleEdit: EditText
    private lateinit var latEdit: EditText
    private lateinit var lonEdit: EditText

    // Technical Details: Checks & Logs (collapsible, closed by default)
    private lateinit var detailsToggleBtn: Button
    private lateinit var detailsSection: LinearLayout
    private lateinit var summaryView: TextView
    private lateinit var checksView: TextView
    private lateinit var logsView: TextView

    private var secretStore: KeystoreSecretStore? = null
    private var suppressSwitch = false
    private var uiMode: String = MODE_RESPONDER
    private var renderedBallotCase: String? = null
    private val seatSpinners = mutableListOf<Spinner>()
    private val mainHandler = Handler(Looper.getMainLooper())

    private val stateListener: (AppSnapshot) -> Unit = { snap ->
        runOnUiThread { render(snap) }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        requestRuntimePermissions()
        setContentView(buildUi())
        try {
            secretStore = KeystoreSecretStore(applicationContext)
        } catch (e: Exception) {
            BitaidState.update {
                it.copy(
                    status = ServiceStatus.FAULT,
                    statusDetail = "The secure store cannot be opened: ${e.message}",
                )
            }
        }
        loadPrefs()
        val savedMode = getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString("ui_mode", "").orEmpty()
        if (savedMode == MODE_CALLER || savedMode == MODE_RESPONDER) {
            applyMode(savedMode, persist = false)
        } else {
            applyMode(MODE_RESPONDER, persist = false)
            showFirstLaunchModeDialog()
        }
    }

    private val ballotCountdownTick = object : Runnable {
        override fun run() {
            val bp = BitaidState.snapshot.ballotDue
            if (bp != null) {
                updateBallotCountdown(bp)
                mainHandler.postDelayed(this, 1000L)
            }
        }
    }

    override fun onStart() {
        super.onStart()
        BitaidState.addListener(stateListener)
    }

    override fun onStop() {
        mainHandler.removeCallbacks(ballotCountdownTick)
        BitaidState.removeListener(stateListener)
        savePrefs()
        super.onStop()
    }

    private fun showFirstLaunchModeDialog() {
        AlertDialog.Builder(this)
            .setTitle("How will you use Bitaid?")
            .setMessage("Choose your main screen. You can switch modes at any time from the top of the screen.")
            .setCancelable(false)
            .setPositiveButton("To help others") { _, _ ->
                applyMode(MODE_RESPONDER, persist = true)
            }
            .setNegativeButton("To ask for help") { _, _ ->
                applyMode(MODE_CALLER, persist = true)
            }
            .show()
    }

    private fun applyMode(mode: String, persist: Boolean) {
        uiMode = if (mode == MODE_CALLER) MODE_CALLER else MODE_RESPONDER
        val isCaller = uiMode == MODE_CALLER

        callerSection.visibility = if (isCaller) View.VISIBLE else View.GONE
        responderSection.visibility = if (isCaller) View.GONE else View.VISIBLE
        responderSettingsSection.visibility = if (isCaller) View.GONE else View.VISIBLE

        styleTabButton(callerTabBtn, active = isCaller)
        styleTabButton(responderTabBtn, active = !isCaller)

        if (persist) {
            getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
                .putString("ui_mode", uiMode)
                .apply()
        }
        render(BitaidState.snapshot)
    }

    private fun styleTabButton(btn: Button, active: Boolean) {
        if (active) {
            btn.setBackgroundColor(Color.parseColor("#1565C0"))
            btn.setTextColor(Color.WHITE)
            btn.setTypeface(null, Typeface.BOLD)
        } else {
            btn.setBackgroundColor(Color.parseColor("#E0E0E0"))
            btn.setTextColor(Color.DKGRAY)
            btn.setTypeface(null, Typeface.NORMAL)
        }
    }

    private fun buildUi(): View {
        val pad = (16 * resources.displayMetrics.density).toInt()
        val halfPad = pad / 2
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad)
        }

        // Mode switcher tabs
        val modeRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, 0, 0, halfPad)
        }
        callerTabBtn = Button(this).apply {
            text = "Ask for help"
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply {
                setMargins(0, 0, halfPad / 2, 0)
            }
            setOnClickListener { applyMode(MODE_CALLER, persist = true) }
        }
        responderTabBtn = Button(this).apply {
            text = "Help others"
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply {
                setMargins(halfPad / 2, 0, 0, 0)
            }
            setOnClickListener { applyMode(MODE_RESPONDER, persist = true) }
        }
        modeRow.addView(callerTabBtn)
        modeRow.addView(responderTabBtn)
        root.addView(modeRow)

        // Status header
        statusView = TextView(this).apply {
            textSize = 18f
            setTypeface(null, Typeface.BOLD)
            setPadding(0, 4, 0, 2)
        }
        progressView = TextView(this).apply {
            textSize = 12f
            setTextColor(Color.DKGRAY)
            setPadding(0, 0, 0, halfPad)
            visibility = View.GONE
        }
        root.addView(statusView)
        root.addView(progressView)

        warningBanner = TextView(this).apply {
            textSize = 14f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.WHITE)
            setBackgroundColor(Color.parseColor("#C62828"))
            val bp = (10 * resources.displayMetrics.density).toInt()
            setPadding(bp, bp, bp, bp)
            visibility = View.GONE
        }
        root.addView(warningBanner)

        // ================= CALLER SCREEN =================
        callerSection = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, halfPad, 0, halfPad)
        }
        callerStateHint = TextView(this).apply {
            textSize = 14f
            setTextColor(Color.DKGRAY)
            setPadding(0, 0, 0, halfPad)
            text = "Connect to your home node first, then press SOS if you need help."
        }
        callerSection.addView(callerStateHint)

        sosBtn = Button(this).apply {
            text = "SOS — ASK FOR HELP"
            textSize = 18f
            setTypeface(null, Typeface.BOLD)
            setBackgroundColor(Color.parseColor("#B71C1C"))
            setTextColor(Color.WHITE)
            setPadding(pad, pad, pad, pad)
            isEnabled = false
            setOnClickListener {
                sosBtn.isEnabled = false
                BitaidState.update { it.copy(statusDetail = "Getting your GPS location (up to 10 s)...") }
                requestFreshFix { fix ->
                    if (fix != null) {
                        NativeBridge.sendRaiseAlert(true, fix.first, fix.second)
                    } else {
                        val manual = manualCoords()
                        if (manual != null) {
                            NativeBridge.sendRaiseAlert(true, manual.first, manual.second)
                        } else {
                            NativeBridge.sendRaiseAlert(false, 0.0, 0.0)
                        }
                    }
                }
            }
        }
        callerSection.addView(sosBtn)

        val callerSubRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, halfPad, 0, 0)
        }
        prepareCallerBtn = Button(this).apply {
            text = "Connect"
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            setOnClickListener {
                savePrefs()
                startRoleService(BitaidService.ACTION_START_CALLER)
            }
        }
        cancelCallerBtn = Button(this).apply {
            text = "Cancel"
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            setOnClickListener { sendServiceAction(BitaidService.ACTION_STOP) }
        }
        callerSubRow.addView(prepareCallerBtn)
        callerSubRow.addView(cancelCallerBtn)
        callerSection.addView(callerSubRow)
        root.addView(callerSection)

        // ================= RESPONDER SCREEN =================
        responderSection = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, halfPad, 0, halfPad)
        }

        dutySwitch = Switch(this).apply {
            text = "Go on duty"
            textSize = 16f
            setTypeface(null, Typeface.BOLD)
            setOnCheckedChangeListener { _, isChecked ->
                if (suppressSwitch) return@setOnCheckedChangeListener
                savePrefs()
                if (isChecked) {
                    startRoleService(BitaidService.ACTION_START_RESPONDER)
                } else {
                    sendServiceAction(BitaidService.ACTION_STOP)
                }
            }
        }
        responderSection.addView(dutySwitch)
        responderSection.addView(helpText("While on duty, alerts near you reach this phone, even with the screen off."))

        batteryBtn = Button(this).apply {
            text = "Keep running with the screen off"
            setOnClickListener { requestBatteryExemption() }
        }
        responderSection.addView(batteryBtn)

        // Incoming Alert card
        alertCard = cardBox("#FFF3E0").apply { visibility = View.GONE }
        alertText = TextView(this).apply {
            textSize = 15f
            setTypeface(null, Typeface.BOLD)
        }
        alertDetailsBtn = Button(this).apply {
            text = "Details"
            textSize = 12f
            setOnClickListener {
                val show = alertDetailsText.visibility != View.VISIBLE
                alertDetailsText.visibility = if (show) View.VISIBLE else View.GONE
                text = if (show) "Hide details" else "Details"
            }
        }
        alertDetailsText = TextView(this).apply {
            textSize = 12f
            typeface = Typeface.MONOSPACE
            setTextColor(Color.DKGRAY)
            visibility = View.GONE
        }
        acceptBtn = Button(this).apply {
            text = "Accept"
            setBackgroundColor(Color.parseColor("#2E7D32"))
            setTextColor(Color.WHITE)
            setOnClickListener {
                BitaidState.snapshot.alert?.let { a ->
                    BitaidState.markAcceptedNow()
                    NativeBridge.sendAccept(a.caseId)
                    BitaidState.update {
                        it.copy(
                            alert = null,
                            status = ServiceStatus.ACTIVE_CASE,
                            statusDetail = "Accepted — waiting for exact location",
                        )
                    }
                }
            }
        }
        declineBtn = Button(this).apply {
            text = "Decline"
            setOnClickListener {
                BitaidState.snapshot.alert?.let { a ->
                    NativeBridge.sendDecline(a.caseId)
                    BitaidState.update { it.copy(alert = null) }
                }
            }
        }
        val alertBtns = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            addView(acceptBtn)
            addView(declineBtn)
            addView(alertDetailsBtn)
        }
        alertCard.addView(alertText)
        alertCard.addView(alertDetailsText)
        alertCard.addView(alertBtns)
        responderSection.addView(alertCard)

        // Verified Location card
        locCard = cardBox("#E8F5E9").apply { visibility = View.GONE }
        locText = TextView(this).apply { textSize = 15f }
        mapsBtn = Button(this).apply {
            text = "Open in Maps"
            setOnClickListener {
                BitaidState.snapshot.location?.let { loc ->
                    val uri = Uri.parse("geo:${loc.lat},${loc.lon}?q=${loc.lat},${loc.lon}(Bitaid+Alert)")
                    startActivity(Intent(Intent.ACTION_VIEW, uri))
                }
            }
        }
        locCard.addView(locText)
        locCard.addView(mapsBtn)
        responderSection.addView(locCard)

        // Ballot card
        ballotCard = cardBox("#E3F2FD").apply { visibility = View.GONE }
        ballotCard.addView(TextView(this).apply {
            text = "How did each responder act?"
            textSize = 16f
            setTypeface(null, Typeface.BOLD)
        })
        ballotCard.addView(helpText("For each person who came: Intervened, Documented, or Neither."))
        ballotCountdownText = TextView(this).apply {
            textSize = 13f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.parseColor("#B71C1C"))
            setPadding(0, 4, 0, 8)
        }
        ballotCard.addView(ballotCountdownText)
        ballotSeatsBox = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        achievedCheck = CheckBox(this).apply { text = "The emergency was resolved"; isChecked = true }
        misuseCheck = CheckBox(this).apply { text = "Someone used more force than needed"; isChecked = false }
        voteBtn = Button(this).apply {
            text = "Submit my vote"
            setOnClickListener {
                val prompt = BitaidState.snapshot.ballotDue ?: return@setOnClickListener
                val arr = JSONArray()
                for (sp in seatSpinners) {
                    val code = when (sp.selectedItem.toString()) {
                        "Intervened" -> "I"
                        "Documented" -> "D"
                        else -> "N"
                    }
                    arr.put(code)
                }
                val ok = NativeBridge.sendVote(prompt.caseId, arr.toString(), achievedCheck.isChecked, misuseCheck.isChecked)
                if (ok) {
                    BitaidState.update { it.copy(ballotDue = null) }
                } else {
                    BitaidState.update { it.copy(logs = (it.logs + "[app] Vote not sent (invalid ballot)").takeLast(200)) }
                }
            }
        }
        ballotCard.addView(ballotSeatsBox)
        ballotCard.addView(achievedCheck)
        ballotCard.addView(misuseCheck)
        ballotCard.addView(voteBtn)
        responderSection.addView(ballotCard)

        root.addView(responderSection)

        // ================= SETTINGS: CONNECTION (shared) =================
        root.addView(sectionHeader("Connection"))
        root.addView(helpText("How this phone reaches your own Bitaid node at home."))

        nameEdit = labeledEditWithHelp(
            root,
            "Name of this phone",
            "Only you see it, in your node's logs.",
            "phone1",
        )
        peerEdit = labeledEditWithHelp(
            root,
            "Your home node's address",
            "The private Tor address of your Bitaid node (.onion:port). It's in app_light.txt on your PC.",
            "",
        )

        root.addView(Button(this).apply {
            text = "Paste connection details"
            setOnClickListener { pasteLightConfigFromClipboard() }
        })
        root.addView(helpText("Copy all of app_light.txt from your PC, then tap here. It fills the three fields below."))

        coreKeyEdit = labeledEditWithHelp(
            root,
            "Your home node's key",
            "Lets the phone be sure it's talking to your node and nobody else (64-hex Core pubkey).",
            "",
        )
        tipSourcesEdit = labeledEditWithHelp(
            root,
            "Second opinions",
            "Two other nodes the phone checks your node against before signing anything with money in it (Tip sources).",
            "",
        )
        anchorEdit = labeledEditWithHelp(
            root,
            "Starting block (optional)",
            "A recent block the phone trusts as its starting point, so it doesn't download the chain's history (height:hash).",
            "",
        )

        // ================= SETTINGS: WALLET (Responder) =================
        responderSettingsSection = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }
        responderSettingsSection.addView(sectionHeader("Wallet"))
        responderSettingsSection.addView(TextView(this).apply {
            text = "Your wallet's address"
            textSize = 13f
            setTypeface(null, Typeface.BOLD)
        })
        responderSettingsSection.addView(helpText("Where your bond and payouts come from. Stored encrypted on this phone."))
        val rpcStatusRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        rpcStatusView = TextView(this).apply { text = "Not set"; textSize = 13f }
        rpcReplaceBtn = Button(this).apply {
            text = "Set"
            setOnClickListener {
                rpcEdit.setText("")
                rpcInputRow.visibility = View.VISIBLE
            }
        }
        rpcStatusRow.addView(rpcStatusView)
        rpcStatusRow.addView(rpcReplaceBtn)
        responderSettingsSection.addView(rpcStatusRow)

        rpcInputRow = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            visibility = View.GONE
        }
        rpcEdit = EditText(this).apply {
            isSingleLine = true
            hint = "http://user:pass@....onion:38332"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        rpcShowCheck = CheckBox(this).apply {
            text = "Show"
            setOnCheckedChangeListener { _, show ->
                rpcEdit.inputType = if (show) {
                    InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
                } else {
                    InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
                }
                rpcEdit.setSelection(rpcEdit.text.length)
            }
        }
        rpcSaveBtn = Button(this).apply {
            text = "Save (encrypted)"
            setOnClickListener {
                val url = rpcEdit.text.toString().trim()
                if (url.isNotEmpty()) {
                    secretStore?.putRpcUrl(url)
                    rpcEdit.setText("")
                    rpcInputRow.visibility = View.GONE
                    refreshRpcStatus()
                }
            }
        }
        rpcInputRow.addView(rpcEdit)
        rpcInputRow.addView(rpcShowCheck)
        rpcInputRow.addView(rpcSaveBtn)
        responderSettingsSection.addView(rpcInputRow)

        walletEdit = labeledEditWithHelp(
            responderSettingsSection,
            "Wallet name",
            "The wallet's name inside your node. Leave as is unless you changed it.",
            "w",
        )
        root.addView(responderSettingsSection)

        // ================= ADVANCED / TEST NETWORK (collapsed by default) =================
        advancedToggleBtn = Button(this).apply {
            text = "Show test network & location overrides"
            setOnClickListener {
                val show = advancedSection.visibility != View.VISIBLE
                advancedSection.visibility = if (show) View.VISIBLE else View.GONE
                text = if (show) "Hide test network & location overrides" else "Show test network & location overrides"
            }
        }
        root.addView(advancedToggleBtn)

        advancedSection = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            visibility = View.GONE
        }
        poolEdit = labeledEditWithHelp(
            advancedSection,
            "Pool name",
            "The oracle pool name (bitaid or tor1).",
            "bitaid",
        )
        satScaleEdit = labeledEditWithHelp(
            advancedSection,
            "Amount scale (BITAID_SAT_SCALE)",
            "1 for local/custom signet, 100 for anchored.",
            "1",
        )
        timeScaleEdit = labeledEditWithHelp(
            advancedSection,
            "Time scale (BITAID_TIME_SCALE)",
            "1 for 20-second signet blocks, 30 for 10-minute blocks.",
            "1",
        )
        latEdit = labeledEditWithHelp(
            advancedSection,
            "Manual latitude (optional)",
            "Leave blank to use GPS.",
            "",
        )
        lonEdit = labeledEditWithHelp(
            advancedSection,
            "Manual longitude (optional)",
            "Leave blank to use GPS.",
            "",
        )
        root.addView(advancedSection)

        // ================= DETAILS: CHECKS & LOGS (collapsed by default) =================
        detailsToggleBtn = Button(this).apply {
            text = "Show details (checks & logs)"
            setOnClickListener {
                val show = detailsSection.visibility != View.VISIBLE
                detailsSection.visibility = if (show) View.VISIBLE else View.GONE
                text = if (show) "Hide details (checks & logs)" else "Show details (checks & logs)"
            }
        }
        root.addView(detailsToggleBtn)

        detailsSection = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            visibility = View.GONE
        }
        val checksHeaderRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        checksHeaderRow.addView(sectionHeader("What this phone has verified  "))
        checksHeaderRow.addView(Button(this).apply {
            text = "Copy report"
            setOnClickListener { copyLogsToClipboard() }
        })
        detailsSection.addView(checksHeaderRow)
        detailsSection.addView(helpText("For sending to whoever helps you test."))
        summaryView = TextView(this).apply { setTypeface(null, Typeface.BOLD) }
        checksView = TextView(this).apply {
            typeface = Typeface.MONOSPACE
            textSize = 12f
        }
        detailsSection.addView(summaryView)
        detailsSection.addView(checksView)

        detailsSection.addView(sectionHeader("Logs"))
        logsView = TextView(this).apply {
            typeface = Typeface.MONOSPACE
            textSize = 11f
        }
        detailsSection.addView(logsView)
        root.addView(detailsSection)

        return ScrollView(this).apply { addView(root) }
    }

    private fun plainStatusLabel(status: ServiceStatus): String = when (status) {
        ServiceStatus.OFF_DUTY -> if (uiMode == MODE_CALLER) "Not connected" else "Off duty"
        ServiceStatus.BOOTSTRAPPING_TOR -> "Connecting privately"
        ServiceStatus.CONNECTING -> "Connecting"
        ServiceStatus.ON_DUTY -> "On duty"
        ServiceStatus.CALLER_READY -> "Ready to ask for help"
        ServiceStatus.ACTIVE_CASE -> if (uiMode == MODE_CALLER) "Help requested" else "Responding"
        ServiceStatus.FAULT -> "Stopped: needs attention"
    }

    private fun copyLogsToClipboard() {
        val snap = BitaidState.snapshot
        val sb = StringBuilder()
        sb.append("Status: ").append(snap.status.name).append(" — ").append(snap.statusDetail).append('\n')
        sb.append("Summary: ").append(snap.passed).append(" passed, ").append(snap.failed).append(" failed\n\n")
        sb.append("=== Live Checks ===\n")
        for (c in snap.checks) {
            val tag = if (c.ok) "PASS" else "FAIL"
            val tail = if (c.detail.isNotBlank()) " (${c.detail})" else ""
            sb.append('[').append(tag).append("] ").append(c.what).append(tail).append('\n')
        }
        sb.append("\n=== Logs ===\n")
        for (line in snap.logs) {
            sb.append(line).append('\n')
        }
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("Bitaid Report", sb.toString()))
        Toast.makeText(this, "Copied report to clipboard", Toast.LENGTH_SHORT).show()
    }

    private fun pasteLightConfigFromClipboard() {
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val raw = cm.primaryClip?.getItemAt(0)?.coerceToText(this)?.toString()?.trim().orEmpty()
        if (raw.isEmpty()) {
            Toast.makeText(this, "Clipboard is empty", Toast.LENGTH_SHORT).show()
            return
        }
        var coreKey = ""
        var tipSources = ""
        var anchor = ""
        var corePeer = ""

        val lines = raw.lines().map { it.trim() }.filter { it.isNotEmpty() }
        if (lines.size == 1 && raw.contains('|')) {
            val parts = raw.split('|').map { it.trim() }
            if (parts.isNotEmpty()) coreKey = parts[0]
            if (parts.size > 1) tipSources = parts[1]
            if (parts.size > 2) anchor = parts[2]
        } else {
            for (line in lines) {
                val lower = line.lowercase()
                when {
                    lower.startsWith("core pubkey:") -> coreKey = line.substringAfter(':').trim()
                    lower.startsWith("tip sources:") -> tipSources = line.substringAfter(':').trim()
                    lower.startsWith("anchor:") -> anchor = line.substringAfter(':').trim()
                    lower.startsWith("core peer:") -> corePeer = line.substringAfter(':').trim()
                }
            }
        }

        var filled = 0
        if (corePeer.isNotEmpty()) {
            peerEdit.setText(corePeer)
            filled++
        }
        if (coreKey.isNotEmpty()) {
            coreKeyEdit.setText(coreKey)
            filled++
        }
        if (tipSources.isNotEmpty()) {
            tipSourcesEdit.setText(tipSources)
            filled++
        }
        if (anchor.isNotEmpty()) {
            anchorEdit.setText(anchor)
            filled++
        }
        if (filled == 0) {
            Toast.makeText(
                this,
                "Clipboard did not match app_light.txt (Core pubkey / Tip sources / Anchor)",
                Toast.LENGTH_LONG,
            ).show()
            return
        }
        savePrefs()
        Toast.makeText(this, "Pasted $filled connection field(s)", Toast.LENGTH_SHORT).show()
    }

    private fun refreshRpcStatus() {
        try {
            val stored = secretStore?.getRpcUrl().orEmpty()
            if (stored.isNotEmpty()) {
                rpcStatusView.text = "Stored (encrypted)  "
                rpcReplaceBtn.text = "Replace"
            } else {
                rpcStatusView.text = "Not set  "
                rpcReplaceBtn.text = "Set"
            }
        } catch (e: Exception) {
            rpcStatusView.text = "Unreadable (${e.message})  "
        }
    }

    private fun render(snap: AppSnapshot) {
        val label = plainStatusLabel(snap.status)
        statusView.text = if (snap.statusDetail.isNotBlank() && !snap.statusDetail.equals(label, ignoreCase = true)) {
            "$label — ${snap.statusDetail}"
        } else {
            label
        }
        statusView.setTextColor(
            when (snap.status) {
                ServiceStatus.FAULT -> Color.parseColor("#B71C1C")
                ServiceStatus.ON_DUTY, ServiceStatus.ACTIVE_CASE, ServiceStatus.CALLER_READY -> Color.parseColor("#1B5E20")
                ServiceStatus.CONNECTING, ServiceStatus.BOOTSTRAPPING_TOR -> Color.parseColor("#E65100")
                else -> Color.DKGRAY
            }
        )

        if ((snap.status == ServiceStatus.CONNECTING || snap.status == ServiceStatus.BOOTSTRAPPING_TOR) &&
            snap.lastProgress.isNotBlank()
        ) {
            progressView.visibility = View.VISIBLE
            progressView.text = snap.lastProgress
        } else {
            progressView.visibility = View.GONE
        }

        if (!snap.warning.isNullOrBlank()) {
            warningBanner.visibility = View.VISIBLE
            warningBanner.text = "Signing is off: your home node gave a wrong answer.\n${snap.warning}"
        } else {
            warningBanner.visibility = View.GONE
        }

        suppressSwitch = true
        dutySwitch.isChecked = snap.status == ServiceStatus.ON_DUTY ||
            snap.status == ServiceStatus.ACTIVE_CASE ||
            snap.status == ServiceStatus.CONNECTING ||
            (snap.status == ServiceStatus.BOOTSTRAPPING_TOR && dutySwitch.isChecked)
        suppressSwitch = false

        sosBtn.isEnabled = snap.status == ServiceStatus.CALLER_READY
        callerStateHint.text = when (snap.status) {
            ServiceStatus.CALLER_READY -> "Connected. Press the red SOS button to ask for help."
            ServiceStatus.BOOTSTRAPPING_TOR, ServiceStatus.CONNECTING -> "Connecting to your home node..."
            ServiceStatus.ACTIVE_CASE -> "Help requested. Stay on this screen while responders come."
            ServiceStatus.FAULT -> "Stopped: check your connection details below."
            else -> "Tap Connect first, then press SOS if you need help."
        }

        val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
        batteryBtn.visibility = if (pm.isIgnoringBatteryOptimizations(packageName)) View.GONE else View.VISIBLE

        if (snap.alert != null) {
            alertCard.visibility = View.VISIBLE
            alertText.text = "Emergency nearby\n" +
                "Deposit ${snap.alert.deposit} · Reward ${snap.alert.reward} · Bounty ${snap.alert.bounty} sats"
            alertDetailsText.text = "Case ${snap.alert.caseId.take(8)} · Cell ${snap.alert.cell}"
        } else {
            alertCard.visibility = View.GONE
            alertDetailsText.visibility = View.GONE
            alertDetailsBtn.text = "Details"
        }

        if (snap.location != null) {
            locCard.visibility = View.VISIBLE
            locText.text = "Verified location:\n" +
                "lat=${snap.location.lat}, lon=${snap.location.lon}"
        } else {
            locCard.visibility = View.GONE
        }

        val bp = snap.ballotDue
        if (bp != null) {
            ballotCard.visibility = View.VISIBLE
            updateBallotCountdown(bp)
            mainHandler.removeCallbacks(ballotCountdownTick)
            mainHandler.postDelayed(ballotCountdownTick, 1000L)
            if (renderedBallotCase != bp.caseId || seatSpinners.size != bp.seats) {
                renderedBallotCase = bp.caseId
                ballotSeatsBox.removeAllViews()
                seatSpinners.clear()
                val opts = arrayOf("Intervened", "Documented", "Neither")
                for (i in 0 until bp.seats) {
                    val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
                    val lbl = TextView(this).apply {
                        text = if (i == bp.mySeat) "Responder ${i + 1} (you): " else "Responder ${i + 1}: "
                    }
                    val sp = Spinner(this).apply {
                        adapter = ArrayAdapter(this@MainActivity, android.R.layout.simple_spinner_dropdown_item, opts)
                        setSelection(if (i == bp.mySeat) 0 else 1)
                    }
                    seatSpinners.add(sp)
                    row.addView(lbl)
                    row.addView(sp)
                    ballotSeatsBox.addView(row)
                }
            }
        } else {
            mainHandler.removeCallbacks(ballotCountdownTick)
            ballotCard.visibility = View.GONE
            renderedBallotCase = null
        }

        summaryView.text = "${snap.passed} passed, ${snap.failed} failed"
        checksView.text = snap.checks.takeLast(40).joinToString("\n") { c ->
            val tag = if (c.ok) "PASS" else "FAIL"
            val tail = if (c.detail.isNotBlank()) " (${c.detail})" else ""
            "[$tag] ${c.what}$tail"
        }
        logsView.text = snap.logs.takeLast(40).joinToString("\n")
    }

    private fun updateBallotCountdown(bp: BallotPrompt) {
        if (bp.remainingSecs <= 0L && bp.remainingBlocks <= 0) {
            ballotCountdownText.text = "Voting window closing now — submit immediately"
            return
        }
        val elapsedSecs = ((System.currentTimeMillis() - bp.receivedAtMs).coerceAtLeast(0L)) / 1000L
        val leftSecs = (bp.remainingSecs - elapsedSecs).coerceAtLeast(0L)
        val mins = leftSecs / 60L
        val secs = leftSecs % 60L
        val clock = if (mins > 0L) "${mins}m ${secs}s" else "${secs}s"
        ballotCountdownText.text = if (leftSecs > 0L) {
            "Time left to vote: ~$clock (${bp.remainingBlocks} block(s) at prompt)"
        } else {
            "Estimated time elapsed — waiting for chain cutoff block"
        }
    }

    private fun startRoleService(action: String) {
        val pos = manualCoords() ?: recentLastKnownFix(maxAgeMs = 5 * 60 * 1000L)?.first
        if (action == BitaidService.ACTION_START_RESPONDER && pos == null) {
            BitaidState.update {
                it.copy(status = ServiceStatus.OFF_DUTY, statusDetail = "No GPS location — enable GPS or enter coordinates")
            }
            return
        }
        val intent = Intent(this, BitaidService::class.java).apply {
            this.action = action
            putExtra(BitaidService.EXTRA_NAME, nameEdit.text.toString().trim().ifEmpty { "phone1" })
            putExtra(BitaidService.EXTRA_PEER, peerEdit.text.toString().trim())
            putExtra(BitaidService.EXTRA_CORE_KEY, coreKeyEdit.text.toString().trim())
            putExtra(BitaidService.EXTRA_TIP_SOURCES, tipSourcesEdit.text.toString().trim())
            putExtra(BitaidService.EXTRA_ANCHOR, anchorEdit.text.toString().trim())
            putExtra(BitaidService.EXTRA_WALLET, walletEdit.text.toString().trim().ifEmpty { "w" })
            putExtra(BitaidService.EXTRA_POOL, poolEdit.text.toString().trim().ifEmpty { "bitaid" })
            putExtra(BitaidService.EXTRA_SAT_SCALE, satScaleEdit.text.toString().trim().ifEmpty { "1" })
            putExtra(BitaidService.EXTRA_TIME_SCALE, timeScaleEdit.text.toString().trim().ifEmpty { "1" })
            if (pos != null) {
                putExtra(BitaidService.EXTRA_HAS_LOC, true)
                putExtra(BitaidService.EXTRA_LAT, pos.first)
                putExtra(BitaidService.EXTRA_LON, pos.second)
            } else {
                putExtra(BitaidService.EXTRA_HAS_LOC, false)
            }
        }
        ContextCompat.startForegroundService(this, intent)
    }

    private fun sendServiceAction(action: String) {
        startService(Intent(this, BitaidService::class.java).apply { this.action = action })
    }

    private fun manualCoords(): Pair<Double, Double>? {
        val la = latEdit.text.toString().trim().toDoubleOrNull() ?: return null
        val lo = lonEdit.text.toString().trim().toDoubleOrNull() ?: return null
        if (!la.isFinite() || !lo.isFinite() || la !in -90.0..90.0 || lo !in -180.0..180.0) return null
        return Pair(la, lo)
    }

    @Suppress("DEPRECATION")
    private fun requestFreshFix(onDone: (Pair<Double, Double>?) -> Unit) {
        val hasFine = ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
        if (!hasFine) {
            onDone(null)
            return
        }
        val lm = getSystemService(Context.LOCATION_SERVICE) as LocationManager
        val provider = when {
            lm.isProviderEnabled(LocationManager.GPS_PROVIDER) -> LocationManager.GPS_PROVIDER
            lm.isProviderEnabled(LocationManager.NETWORK_PROVIDER) -> LocationManager.NETWORK_PROVIDER
            else -> null
        }
        if (provider == null) {
            onDone(fallbackRecentFix())
            return
        }
        val finished = AtomicBoolean(false)
        val finish: (Location?) -> Unit = { loc ->
            if (finished.compareAndSet(false, true)) {
                if (loc != null) {
                    onDone(Pair(loc.latitude, loc.longitude))
                } else {
                    onDone(fallbackRecentFix())
                }
            }
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val cs = CancellationSignal()
            mainHandler.postDelayed({
                cs.cancel()
                finish(null)
            }, 10_000L)
            lm.getCurrentLocation(provider, cs, mainExecutor) { loc -> finish(loc) }
        } else {
            val listener = object : LocationListener {
                override fun onLocationChanged(loc: Location) {
                    lm.removeUpdates(this)
                    finish(loc)
                }
            }
            mainHandler.postDelayed({
                lm.removeUpdates(listener)
                finish(null)
            }, 10_000L)
            lm.requestSingleUpdate(provider, listener, Looper.getMainLooper())
        }
    }

    private fun fallbackRecentFix(): Pair<Double, Double>? {
        val recent = recentLastKnownFix(maxAgeMs = 5 * 60 * 1000L)
        if (recent != null) {
            val ageSec = recent.second / 1000L
            BitaidState.update {
                it.copy(logs = (it.logs + "[app] No fresh GPS fix; using cached fix (${ageSec}s old)").takeLast(200))
            }
            return recent.first
        }
        BitaidState.update {
            it.copy(logs = (it.logs + "[app] No recent GPS fix (<5 min); raising alert without position").takeLast(200))
        }
        return null
    }

    private fun recentLastKnownFix(maxAgeMs: Long): Pair<Pair<Double, Double>, Long>? {
        val hasFine = ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
        if (!hasFine) return null
        val lm = getSystemService(Context.LOCATION_SERVICE) as LocationManager
        val best = listOfNotNull(
            lm.getLastKnownLocation(LocationManager.GPS_PROVIDER),
            lm.getLastKnownLocation(LocationManager.NETWORK_PROVIDER),
        ).maxByOrNull { it.time } ?: return null
        val age = (System.currentTimeMillis() - best.time).coerceAtLeast(0L)
        if (age > maxAgeMs) return null
        return Pair(Pair(best.latitude, best.longitude), age)
    }

    private fun requestRuntimePermissions() {
        val need = mutableListOf<String>()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            need.add(Manifest.permission.POST_NOTIFICATIONS)
        }
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            need.add(Manifest.permission.ACCESS_FINE_LOCATION)
        }
        if (need.isNotEmpty()) {
            ActivityCompat.requestPermissions(this, need.toTypedArray(), 100)
        }
    }

    private fun requestBatteryExemption() {
        val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
            data = Uri.parse("package:$packageName")
        }
        startActivity(intent)
    }

    private fun cardBox(bgHex: String): LinearLayout {
        val p = (12 * resources.displayMetrics.density).toInt()
        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.parseColor(bgHex))
            setPadding(p, p, p, p)
        }
    }

    private fun sectionHeader(title: String): TextView = TextView(this).apply {
        text = title
        textSize = 15f
        setTypeface(null, Typeface.BOLD)
        setPadding(0, (12 * resources.displayMetrics.density).toInt(), 0, 4)
    }

    private fun helpText(text: String): TextView = TextView(this).apply {
        this.text = text
        textSize = 12f
        setTextColor(Color.parseColor("#555555"))
        setPadding(0, 0, 0, (6 * resources.displayMetrics.density).toInt())
    }

    private fun labeledEditWithHelp(
        parent: LinearLayout,
        label: String,
        help: String,
        def: String,
    ): EditText {
        parent.addView(TextView(this).apply {
            text = label
            textSize = 13f
            setTypeface(null, Typeface.BOLD)
            setPadding(0, (6 * resources.displayMetrics.density).toInt(), 0, 0)
        })
        parent.addView(helpText(help))
        val et = EditText(this).apply { setText(def); isSingleLine = true }
        parent.addView(et)
        return et
    }

    private fun loadPrefs() {
        val p = getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        nameEdit.setText(p.getString("name", "phone1"))
        peerEdit.setText(p.getString("peer", ""))
        coreKeyEdit.setText(p.getString("core_key", ""))
        tipSourcesEdit.setText(p.getString("tip_sources", ""))
        anchorEdit.setText(p.getString("anchor", ""))
        walletEdit.setText(p.getString("wallet", "w"))
        poolEdit.setText(p.getString("pool", "bitaid"))
        satScaleEdit.setText(p.getString("sat_scale", "1"))
        timeScaleEdit.setText(p.getString("time_scale", "1"))
        latEdit.setText(p.getString("lat", ""))
        lonEdit.setText(p.getString("lon", ""))
        refreshRpcStatus()
    }

    private fun savePrefs() {
        getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString("ui_mode", uiMode)
            .putString("name", nameEdit.text.toString().trim())
            .putString("peer", peerEdit.text.toString().trim())
            .putString("core_key", coreKeyEdit.text.toString().trim())
            .putString("tip_sources", tipSourcesEdit.text.toString().trim())
            .putString("anchor", anchorEdit.text.toString().trim())
            .putString("wallet", walletEdit.text.toString().trim())
            .putString("pool", poolEdit.text.toString().trim())
            .putString("sat_scale", satScaleEdit.text.toString().trim())
            .putString("time_scale", timeScaleEdit.text.toString().trim())
            .putString("lat", latEdit.text.toString().trim())
            .putString("lon", lonEdit.text.toString().trim())
            .remove("rpc")
            .apply()
        val typedRpc = rpcEdit.text.toString().trim()
        if (rpcInputRow.visibility == View.VISIBLE && typedRpc.isNotEmpty()) {
            secretStore?.putRpcUrl(typedRpc)
            rpcEdit.setText("")
            rpcInputRow.visibility = View.GONE
            refreshRpcStatus()
        }
    }

    companion object {
        private const val PREFS = "bitaid_ui_prefs"
        private const val MODE_CALLER = "caller"
        private const val MODE_RESPONDER = "responder"
    }
}
