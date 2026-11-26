package com.bitaid.app

import android.Manifest
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
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import org.json.JSONArray
import java.util.concurrent.atomic.AtomicBoolean

/**
 * M4 step 3: Minimal Kotlin shell around `bitaid-node` + `bitaid-tor`.
 *
 * - Masked RPC URL: once stored encrypted in Keystore, never repopulated into a plaintext EditText.
 * - Live progress line under status while `BOOTSTRAPPING_TOR` / `CONNECTING`.
 * - Configurable `--pool`, `BITAID_SAT_SCALE`, `BITAID_TIME_SCALE`.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var statusView: TextView
    private lateinit var progressView: TextView
    private lateinit var dutySwitch: Switch
    private lateinit var peerEdit: EditText
    private lateinit var rpcStatusView: TextView
    private lateinit var rpcReplaceBtn: Button
    private lateinit var rpcInputRow: LinearLayout
    private lateinit var rpcEdit: EditText
    private lateinit var rpcShowCheck: CheckBox
    private lateinit var rpcSaveBtn: Button
    private lateinit var walletEdit: EditText
    private lateinit var poolEdit: EditText
    private lateinit var satScaleEdit: EditText
    private lateinit var timeScaleEdit: EditText
    private lateinit var nameEdit: EditText
    private lateinit var latEdit: EditText
    private lateinit var lonEdit: EditText
    private lateinit var batteryBtn: Button
    private lateinit var prepareCallerBtn: Button
    private lateinit var sosBtn: Button
    private lateinit var cancelCallerBtn: Button

    private lateinit var alertCard: LinearLayout
    private lateinit var alertText: TextView
    private lateinit var acceptBtn: Button
    private lateinit var declineBtn: Button

    private lateinit var locCard: LinearLayout
    private lateinit var locText: TextView
    private lateinit var mapsBtn: Button

    private lateinit var ballotCard: LinearLayout
    private lateinit var ballotSeatsBox: LinearLayout
    private lateinit var achievedCheck: CheckBox
    private lateinit var misuseCheck: CheckBox
    private lateinit var voteBtn: Button

    private lateinit var summaryView: TextView
    private lateinit var checksView: TextView
    private lateinit var logsView: TextView

    private var secretStore: KeystoreSecretStore? = null
    private var suppressSwitch = false
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
                it.copy(status = ServiceStatus.FAULT, statusDetail = "The secure store cannot be opened: ${e.message}")
            }
        }
        loadPrefs()
    }

    override fun onStart() {
        super.onStart()
        BitaidState.addListener(stateListener)
    }

    override fun onStop() {
        BitaidState.removeListener(stateListener)
        savePrefs()
        super.onStop()
    }

    private fun buildUi(): View {
        val pad = (16 * resources.displayMetrics.density).toInt()
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad)
        }

        statusView = TextView(this).apply {
            textSize = 18f
            setTypeface(null, Typeface.BOLD)
            setPadding(0, 0, 0, 2)
        }
        progressView = TextView(this).apply {
            textSize = 12f
            setTextColor(Color.DKGRAY)
            setPadding(0, 0, 0, pad / 2)
            visibility = View.GONE
        }
        root.addView(statusView)
        root.addView(progressView)

        dutySwitch = Switch(this).apply {
            text = "Responder On Duty (Foreground Service)"
            textSize = 16f
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
        root.addView(dutySwitch)

        // Caller controls
        val callerRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, pad / 2, 0, pad / 2)
        }
        prepareCallerBtn = Button(this).apply {
            text = "Prepare Caller"
            setOnClickListener {
                savePrefs()
                startRoleService(BitaidService.ACTION_START_CALLER)
            }
        }
        sosBtn = Button(this).apply {
            text = "SOS ALERT"
            setBackgroundColor(Color.parseColor("#B71C1C"))
            setTextColor(Color.WHITE)
            isEnabled = false
            setOnClickListener {
                sosBtn.isEnabled = false
                BitaidState.update { it.copy(statusDetail = "Getting fresh GPS fix (up to 10 s)...") }
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
        cancelCallerBtn = Button(this).apply {
            text = "Cancel"
            setOnClickListener { sendServiceAction(BitaidService.ACTION_STOP) }
        }
        callerRow.addView(prepareCallerBtn)
        callerRow.addView(sosBtn)
        callerRow.addView(cancelCallerBtn)
        root.addView(callerRow)

        batteryBtn = Button(this).apply {
            text = "Allow Unrestricted Battery (Screen-Off Duty)"
            setOnClickListener { requestBatteryExemption() }
        }
        root.addView(batteryBtn)

        // Incoming Alert card
        alertCard = cardBox("#FFF3E0").apply { visibility = View.GONE }
        alertText = TextView(this).apply {
            textSize = 15f
            setTypeface(null, Typeface.BOLD)
        }
        acceptBtn = Button(this).apply {
            text = "ACCEPT"
            setBackgroundColor(Color.parseColor("#2E7D32"))
            setTextColor(Color.WHITE)
            setOnClickListener {
                BitaidState.snapshot.alert?.let { a ->
                    BitaidState.markAcceptedNow()
                    NativeBridge.sendAccept(a.caseId)
                    BitaidState.update { it.copy(alert = null, status = ServiceStatus.ACTIVE_CASE, statusDetail = "Accepted — awaiting verified location") }
                }
            }
        }
        declineBtn = Button(this).apply {
            text = "DECLINE"
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
        }
        alertCard.addView(alertText)
        alertCard.addView(alertBtns)
        root.addView(alertCard)

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
        root.addView(locCard)

        // Ballot card
        ballotCard = cardBox("#E3F2FD").apply { visibility = View.GONE }
        ballotCard.addView(TextView(this).apply {
            text = "Ballot Due — classify each seat (I = Intervened, D = Documented, N = Neither)"
            setTypeface(null, Typeface.BOLD)
        })
        ballotSeatsBox = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        achievedCheck = CheckBox(this).apply { text = "Outcome achieved"; isChecked = true }
        misuseCheck = CheckBox(this).apply { text = "Force misused"; isChecked = false }
        voteBtn = Button(this).apply {
            text = "SUBMIT VOTE"
            setOnClickListener {
                val prompt = BitaidState.snapshot.ballotDue ?: return@setOnClickListener
                val arr = JSONArray()
                for (sp in seatSpinners) {
                    arr.put(sp.selectedItem.toString())
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
        root.addView(ballotCard)

        // Settings section
        root.addView(sectionHeader("Signet Settings"))
        nameEdit = labeledEdit(root, "Node name", "phone1")
        peerEdit = labeledEdit(root, "Core peer (.onion:port)", "")

        // Masked RPC URL (never repopulated into plaintext once stored)
        root.addView(TextView(this).apply { text = "Trusted bitcoind RPC (http://user:pass@onion:port)"; textSize = 12f })
        val rpcStatusRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        rpcStatusView = TextView(this).apply { text = "Not set"; textSize = 13f }
        rpcReplaceBtn = Button(this).apply {
            text = "Set / Replace"
            setOnClickListener {
                rpcEdit.setText("")
                rpcInputRow.visibility = View.VISIBLE
            }
        }
        rpcStatusRow.addView(rpcStatusView)
        rpcStatusRow.addView(rpcReplaceBtn)
        root.addView(rpcStatusRow)

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
            text = "Show RPC URL"
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
            text = "Save RPC (Encrypted)"
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
        root.addView(rpcInputRow)

        walletEdit = labeledEdit(root, "RPC wallet", "w")
        poolEdit = labeledEdit(root, "Pool name (bitaid or tor1)", "bitaid")
        satScaleEdit = labeledEdit(root, "BITAID_SAT_SCALE (1 for local/custom signet, 100 for anchored)", "1")
        timeScaleEdit = labeledEdit(root, "BITAID_TIME_SCALE (1 for local/custom signet, 30 for anchored)", "1")
        latEdit = labeledEdit(root, "Override latitude (optional; blank uses GPS)", "")
        lonEdit = labeledEdit(root, "Override longitude (optional; blank uses GPS)", "")

        // Live checks and logs
        root.addView(sectionHeader("Live Checks"))
        summaryView = TextView(this).apply { setTypeface(null, Typeface.BOLD) }
        checksView = TextView(this).apply {
            typeface = Typeface.MONOSPACE
            textSize = 12f
        }
        root.addView(summaryView)
        root.addView(checksView)

        root.addView(sectionHeader("Logs"))
        logsView = TextView(this).apply {
            typeface = Typeface.MONOSPACE
            textSize = 11f
        }
        root.addView(logsView)

        return ScrollView(this).apply { addView(root) }
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
        statusView.text = "${snap.status.name}: ${snap.statusDetail}"
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

        suppressSwitch = true
        dutySwitch.isChecked = snap.status == ServiceStatus.ON_DUTY ||
            snap.status == ServiceStatus.ACTIVE_CASE ||
            snap.status == ServiceStatus.CONNECTING ||
            (snap.status == ServiceStatus.BOOTSTRAPPING_TOR && dutySwitch.isChecked)
        suppressSwitch = false

        sosBtn.isEnabled = snap.status == ServiceStatus.CALLER_READY

        val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
        batteryBtn.visibility = if (pm.isIgnoringBatteryOptimizations(packageName)) View.GONE else View.VISIBLE

        if (snap.alert != null) {
            alertCard.visibility = View.VISIBLE
            alertText.text = "ALERT ${snap.alert.caseId.take(8)} in cell ${snap.alert.cell}\n" +
                "deposit=${snap.alert.deposit}  reward=${snap.alert.reward}  bounty=${snap.alert.bounty} sats"
        } else {
            alertCard.visibility = View.GONE
        }

        if (snap.location != null) {
            locCard.visibility = View.VISIBLE
            locText.text = "Verified location (${snap.location.caseId.take(8)}):\n" +
                "lat=${snap.location.lat}, lon=${snap.location.lon}"
        } else {
            locCard.visibility = View.GONE
        }

        val bp = snap.ballotDue
        if (bp != null) {
            ballotCard.visibility = View.VISIBLE
            if (renderedBallotCase != bp.caseId || seatSpinners.size != bp.seats) {
                renderedBallotCase = bp.caseId
                ballotSeatsBox.removeAllViews()
                seatSpinners.clear()
                val opts = arrayOf("I", "D", "N")
                for (i in 0 until bp.seats) {
                    val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
                    val lbl = TextView(this).apply {
                        text = if (i == bp.mySeat) "Seat $i (you): " else "Seat $i: "
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

    private fun startRoleService(action: String) {
        val pos = manualCoords() ?: recentLastKnownFix(maxAgeMs = 5 * 60 * 1000L)?.first
        if (action == BitaidService.ACTION_START_RESPONDER && pos == null) {
            BitaidState.update {
                it.copy(status = ServiceStatus.OFF_DUTY, statusDetail = "No position — enable GPS or enter coordinates")
            }
            return
        }
        val intent = Intent(this, BitaidService::class.java).apply {
            this.action = action
            putExtra(BitaidService.EXTRA_NAME, nameEdit.text.toString().trim().ifEmpty { "phone1" })
            putExtra(BitaidService.EXTRA_PEER, peerEdit.text.toString().trim())
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

    private fun labeledEdit(parent: LinearLayout, label: String, def: String): EditText {
        parent.addView(TextView(this).apply { text = label; textSize = 12f })
        val et = EditText(this).apply { setText(def); isSingleLine = true }
        parent.addView(et)
        return et
    }

    private fun loadPrefs() {
        val p = getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        nameEdit.setText(p.getString("name", "phone1"))
        peerEdit.setText(p.getString("peer", ""))
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
            .putString("name", nameEdit.text.toString().trim())
            .putString("peer", peerEdit.text.toString().trim())
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
    }
}
