package com.bitaid.app

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.Typeface
import android.location.LocationManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
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

/**
 * M4 step 3: Minimal Kotlin shell around `bitaid-node` + `bitaid-tor`.
 *
 * Covers both app roles (responder and caller):
 * - On-duty switch (starts/stops `BitaidService` foreground service)
 * - Caller prepare + SOS alert button (uses live GPS fix when pressed)
 * - Incoming alert card (Accept / Decline)
 * - Verified location card (Open in Maps)
 * - Ballot card (one I/D/N per seat, achieved, misuse)
 * - Live PASS/FAIL checks and log stream
 */
class MainActivity : AppCompatActivity() {

    private lateinit var statusView: TextView
    private lateinit var dutySwitch: Switch
    private lateinit var peerEdit: EditText
    private lateinit var rpcEdit: EditText
    private lateinit var walletEdit: EditText
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

    private var suppressSwitch = false
    private var renderedBallotCase: String? = null
    private val seatSpinners = mutableListOf<Spinner>()

    private val stateListener: (AppSnapshot) -> Unit = { snap ->
        runOnUiThread { render(snap) }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        requestRuntimePermissions()
        setContentView(buildUi())
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
            setPadding(0, 0, 0, pad / 2)
        }
        root.addView(statusView)

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
                val gps = currentGpsFix()
                if (gps != null) {
                    NativeBridge.sendRaiseAlert(true, gps.first, gps.second)
                } else {
                    val la = latEdit.text.toString().toDoubleOrNull()
                    val lo = lonEdit.text.toString().toDoubleOrNull()
                    if (la != null && lo != null) {
                        NativeBridge.sendRaiseAlert(true, la, lo)
                    } else {
                        NativeBridge.sendRaiseAlert(false, 0.0, 0.0)
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
                NativeBridge.sendVote(prompt.caseId, arr.toString(), achievedCheck.isChecked, misuseCheck.isChecked)
                BitaidState.update { it.copy(ballotDue = null) }
            }
        }
        ballotCard.addView(ballotSeatsBox)
        ballotCard.addView(achievedCheck)
        ballotCard.addView(misuseCheck)
        ballotCard.addView(voteBtn)
        root.addView(ballotCard)

        // Settings section (non-secret test-chain configuration)
        root.addView(sectionHeader("Signet Settings (non-secret)"))
        nameEdit = labeledEdit(root, "Node name", "phone1")
        peerEdit = labeledEdit(root, "Core peer (.onion:port)", "")
        rpcEdit = labeledEdit(root, "Trusted bitcoind RPC (http://user:pass@onion:port)", "")
        walletEdit = labeledEdit(root, "RPC wallet", "w")
        latEdit = labeledEdit(root, "Default latitude", "13.6929")
        lonEdit = labeledEdit(root, "Default longitude", "-89.2182")

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

    private fun render(snap: AppSnapshot) {
        statusView.text = "${snap.status.name}: ${snap.statusDetail}"
        statusView.setTextColor(
            when (snap.status) {
                ServiceStatus.FAULT -> Color.parseColor("#B71C1C")
                ServiceStatus.ON_DUTY, ServiceStatus.ACTIVE_CASE, ServiceStatus.CALLER_READY -> Color.parseColor("#1B5E20")
                else -> Color.DKGRAY
            }
        )

        suppressSwitch = true
        dutySwitch.isChecked = snap.status == ServiceStatus.ON_DUTY ||
            snap.status == ServiceStatus.ACTIVE_CASE ||
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
        val intent = Intent(this, BitaidService::class.java).apply {
            this.action = action
            putExtra(BitaidService.EXTRA_NAME, nameEdit.text.toString().trim().ifEmpty { "phone1" })
            putExtra(BitaidService.EXTRA_PEER, peerEdit.text.toString().trim())
            putExtra(BitaidService.EXTRA_RPC, rpcEdit.text.toString().trim())
            putExtra(BitaidService.EXTRA_WALLET, walletEdit.text.toString().trim().ifEmpty { "w" })
            putExtra(BitaidService.EXTRA_LAT, latEdit.text.toString().toDoubleOrNull() ?: 13.6929)
            putExtra(BitaidService.EXTRA_LON, lonEdit.text.toString().toDoubleOrNull() ?: -89.2182)
        }
        ContextCompat.startForegroundService(this, intent)
    }

    private fun sendServiceAction(action: String) {
        startService(Intent(this, BitaidService::class.java).apply { this.action = action })
    }

    private fun currentGpsFix(): Pair<Double, Double>? {
        val hasFine = ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
        if (!hasFine) return null
        val lm = getSystemService(Context.LOCATION_SERVICE) as LocationManager
        val loc = lm.getLastKnownLocation(LocationManager.GPS_PROVIDER)
            ?: lm.getLastKnownLocation(LocationManager.NETWORK_PROVIDER)
            ?: return null
        return Pair(loc.latitude, loc.longitude)
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
        rpcEdit.setText(p.getString("rpc", ""))
        walletEdit.setText(p.getString("wallet", "w"))
        latEdit.setText(p.getString("lat", "13.6929"))
        lonEdit.setText(p.getString("lon", "-89.2182"))
    }

    private fun savePrefs() {
        getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString("name", nameEdit.text.toString().trim())
            .putString("peer", peerEdit.text.toString().trim())
            .putString("rpc", rpcEdit.text.toString().trim())
            .putString("wallet", walletEdit.text.toString().trim())
            .putString("lat", latEdit.text.toString().trim())
            .putString("lon", lonEdit.text.toString().trim())
            .apply()
    }

    companion object {
        private const val PREFS = "bitaid_ui_prefs"
    }
}
