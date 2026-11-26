package com.bitaid.app

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * M4 step 4: Foreground service keeping Arti Tor and the active role alive with screen off.
 *
 * - Flips to `ON_DUTY` only on `Event::Listening` (shows `CONNECTING` until then).
 * - Passes `--exit-after 86400`, `--settle-wait 1800`, `--pool`, `BITAID_SAT_SCALE`, `BITAID_TIME_SCALE`.
 * - If `startRole` reports `"role still running"`, queues the config and relaunches on `RoleExited`
 *   instead of reporting a fault.
 */
class BitaidService : Service() {

    private val worker = Executors.newSingleThreadScheduledExecutor()
    private val wantOnDuty = AtomicBoolean(false)

    private var secretStore: KeystoreSecretStore? = null
    private var storeInitError: String? = null
    private var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    @Volatile
    private var lastNetworkHandle: Long? = null

    @Volatile
    private var pendingRelaunch: RoleLaunchConfig? = null

    private var wakeLock: PowerManager.WakeLock? = null
    private var roleStartedAtMs: Long = 0L
    private var consecutiveQuickFails: Int = 0

    data class RoleLaunchConfig(
        val role: String,
        val nodeName: String,
        val peerOnion: String,
        val wallet: String,
        val pool: String,
        val satScale: String,
        val timeScale: String,
        val lat: Double?,
        val lon: Double?,
    )

    override fun onCreate() {
        super.onCreate()
        createChannels()
        try {
            val store = KeystoreSecretStore(applicationContext)
            secretStore = store
            if (!NativeBridge.installSecretStore(store)) {
                storeInitError = "Failed to install SecretStore in native layer"
            }
        } catch (e: Exception) {
            storeInitError = "The secure store cannot be opened: ${e.message}"
        }
        registerFilteredNetworkCallback()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START_RESPONDER, ACTION_START_CALLER -> {
                val initErr = storeInitError
                if (initErr != null || secretStore == null) {
                    faultAndStop(initErr ?: "The secure store cannot be opened")
                    return START_NOT_STICKY
                }
                val role = if (intent.action == ACTION_START_CALLER) "caller" else "responder"
                val hasLoc = intent.getBooleanExtra(EXTRA_HAS_LOC, false)
                val lat = if (hasLoc) intent.getDoubleExtra(EXTRA_LAT, Double.NaN) else null
                val lon = if (hasLoc) intent.getDoubleExtra(EXTRA_LON, Double.NaN) else null
                val validLoc = lat != null && lon != null && lat.isFinite() && lon.isFinite() &&
                    lat in -90.0..90.0 && lon in -180.0..180.0

                if (role == "responder" && !validLoc) {
                    faultAndStop("No position — cannot go on duty")
                    return START_NOT_STICKY
                }

                val cfg = RoleLaunchConfig(
                    role = role,
                    nodeName = intent.getStringExtra(EXTRA_NAME) ?: role,
                    peerOnion = intent.getStringExtra(EXTRA_PEER) ?: "",
                    wallet = intent.getStringExtra(EXTRA_WALLET) ?: "w",
                    pool = intent.getStringExtra(EXTRA_POOL) ?: "bitaid",
                    satScale = intent.getStringExtra(EXTRA_SAT_SCALE) ?: "1",
                    timeScale = intent.getStringExtra(EXTRA_TIME_SCALE) ?: "1",
                    lat = if (validLoc) lat else null,
                    lon = if (validLoc) lon else null,
                )
                consecutiveQuickFails = 0
                wantOnDuty.set(true)
                promoteForeground("Starting Tor ($role)...")
                acquireWakeLock()
                worker.execute { startTorAndRole(cfg) }
            }
            ACTION_STOP -> {
                wantOnDuty.set(false)
                pendingRelaunch = null
                NativeBridge.sendOffDuty()
                BitaidState.update {
                    it.copy(
                        status = ServiceStatus.OFF_DUTY,
                        statusDetail = "Going off duty...",
                        alert = null,
                        ballotDue = null,
                    )
                }
            }
        }
        return START_NOT_STICKY
    }

    private fun faultAndStop(reason: String) {
        wantOnDuty.set(false)
        pendingRelaunch = null
        BitaidState.update {
            it.copy(
                status = ServiceStatus.FAULT,
                statusDetail = reason,
                alert = null,
                ballotDue = null,
            )
        }
        updateNotification("FAULT: $reason")
        releaseWakeLock()
        stopSelf()
    }

    private fun startTorAndRole(cfg: RoleLaunchConfig) {
        BitaidState.update {
            it.copy(
                status = ServiceStatus.BOOTSTRAPPING_TOR,
                statusDetail = "Bootstrapping in-process Arti Tor...",
            )
        }
        val stateDir = File(noBackupFilesDir, "arti/state").absolutePath
        val cacheDir = File(cacheDir, "arti/cache").absolutePath
        val err = NativeBridge.startTor(stateDir, cacheDir)
        if (err.isNotEmpty()) {
            faultAndStop("Tor failed: $err")
            return
        }
        NativeBridge.setTorDormant(false)
        launchRole(cfg)
    }

    private fun launchRole(cfg: RoleLaunchConfig) {
        if (!wantOnDuty.get()) {
            finishOffDuty()
            return
        }
        val store = secretStore ?: run {
            faultAndStop("The secure store cannot be opened")
            return
        }
        val identityHex = try {
            store.getOrCreateIdentityHex(cfg.nodeName)
        } catch (e: Exception) {
            faultAndStop("Identity key unreadable: ${e.message}")
            return
        }
        val rpcUrl = try {
            store.getRpcUrl()
        } catch (e: Exception) {
            faultAndStop("RPC credentials unreadable: ${e.message}")
            return
        }

        val settings = JSONObject().apply {
            put("HOME", filesDir.absolutePath)
            put("BITAID_RPC", rpcUrl)
            put("BITAID_WALLET", cfg.wallet)
            put("BITAID_REPLY_MIN", "900")
            put("BITAID_SAT_SCALE", cfg.satScale.ifBlank { "1" })
            put("BITAID_TIME_SCALE", cfg.timeScale.ifBlank { "1" })
        }

        val args = JSONArray().apply {
            put("bitaid-node")
            put("--role"); put(cfg.role)
            put("--name"); put(cfg.nodeName)
            put("--secret"); put(identityHex)
            if (cfg.pool.isNotBlank()) {
                put("--pool"); put(cfg.pool)
            }
            if (cfg.peerOnion.isNotBlank()) {
                put("--peer"); put(cfg.peerOnion)
            }
            if (cfg.lat != null && cfg.lon != null) {
                put("--lat"); put(cfg.lat.toString())
                put("--lon"); put(cfg.lon.toString())
            }
            put("--exit-after"); put("86400")
            put("--settle-wait"); put("1800")
            if (cfg.role == "responder") {
                put("--ask-accept")
                put("--ask-vote")
            } else {
                put("--ask-alert")
            }
        }

        BitaidState.update {
            it.copy(
                status = ServiceStatus.CONNECTING,
                statusDetail = if (cfg.role == "responder") "Connecting to Core & chain over Tor..." else "Preparing caller...",
            )
        }
        updateNotification(if (cfg.role == "responder") "Connecting over Tor..." else "Preparing caller...")
        roleStartedAtMs = System.currentTimeMillis()

        val err = NativeBridge.startRole(
            settings.toString(),
            args.toString(),
            object : EventCallback {
                override fun onEvent(json: String) {
                    val type = BitaidState.applyNativeEvent(json)
                    when (type) {
                        "Listening" -> updateNotification("On duty — listening for alerts")
                        "Alert" -> postAlertNotification()
                        "Location" -> updateNotification("Responding — location verified")
                        "Fatal" -> {
                            wantOnDuty.set(false)
                            pendingRelaunch = null
                            updateNotification("Node fault — stopped")
                            releaseWakeLock()
                            stopSelf()
                        }
                        "RoleExited" -> {
                            val pending = pendingRelaunch
                            if (pending != null && wantOnDuty.get()) {
                                pendingRelaunch = null
                                worker.execute { launchRole(pending) }
                                return
                            }
                            val code = try {
                                JSONObject(json).optInt("code", 1)
                            } catch (_: Exception) {
                                1
                            }
                            if (!wantOnDuty.get() || cfg.role != "responder" || BitaidState.snapshot.status == ServiceStatus.FAULT) {
                                finishOffDuty()
                                return
                            }
                            val ranMs = System.currentTimeMillis() - roleStartedAtMs
                            if (code != 0 && ranMs < QUICK_FAIL_MS) {
                                consecutiveQuickFails += 1
                                if (consecutiveQuickFails >= MAX_QUICK_FAILS) {
                                    faultAndStop("Responder exited repeatedly (code $code)")
                                    return
                                }
                                val backoffMs = 2_000L shl (consecutiveQuickFails - 1)
                                worker.schedule({ launchRole(cfg) }, backoffMs, TimeUnit.MILLISECONDS)
                            } else {
                                consecutiveQuickFails = 0
                                worker.execute { launchRole(cfg) }
                            }
                        }
                    }
                }
            },
        )
        if (err == "role still running") {
            // Previous role is still winding down; wait for RoleExited rather than faulting.
            pendingRelaunch = cfg
            BitaidState.update {
                it.copy(status = ServiceStatus.CONNECTING, statusDetail = "Waiting for previous role to finish...")
            }
            return
        }
        if (err.isNotEmpty()) {
            faultAndStop("Refused to start role: $err")
        }
    }

    private fun finishOffDuty() {
        NativeBridge.setTorDormant(true)
        BitaidState.update {
            if (it.status == ServiceStatus.FAULT) it
            else it.copy(status = ServiceStatus.OFF_DUTY, statusDetail = "Off duty", alert = null, ballotDue = null)
        }
        releaseWakeLock()
        stopSelf()
    }

    private fun registerFilteredNetworkCallback() {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        connectivityManager = cm
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                val handle = network.networkHandle
                val prev = lastNetworkHandle
                lastNetworkHandle = handle
                if (prev != null && prev != handle && wantOnDuty.get()) {
                    worker.execute { NativeBridge.torNetworkChanged() }
                }
            }
        }
        networkCallback = cb
        cm.registerDefaultNetworkCallback(cb)
    }

    private fun promoteForeground(text: String) {
        val hasLoc = ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
        val fgsType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            if (hasLoc) {
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE or ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION
            } else {
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            }
        } else {
            0
        }
        ServiceCompat.startForeground(this, NOTIF_ID, buildNotification(text), fgsType)
    }

    private fun updateNotification(text: String) {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(NOTIF_ID, buildNotification(text))
    }

    private fun buildNotification(text: String): Notification {
        val pi = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return NotificationCompat.Builder(this, CHANNEL_DUTY)
            .setContentTitle("Bitaid (Signet)")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setOngoing(true)
            .setContentIntent(pi)
            .build()
    }

    private fun postAlertNotification() {
        val pi = PendingIntent.getActivity(
            this,
            1,
            Intent(this, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP
            },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val notif = NotificationCompat.Builder(this, CHANNEL_ALERT)
            .setContentTitle("Incoming Bitaid Alert")
            .setContentText("Tap to review and accept or decline")
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setAutoCancel(true)
            .setContentIntent(pi)
            .build()
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(ALERT_NOTIF_ID, notif)
    }

    private fun createChannels() {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_DUTY, "Bitaid On-Duty Service", NotificationManager.IMPORTANCE_LOW)
        )
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_ALERT, "Bitaid Emergency Alerts", NotificationManager.IMPORTANCE_HIGH)
        )
    }

    private fun acquireWakeLock() {
        if (wakeLock?.isHeld == true) return
        val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "bitaid:duty").apply {
            setReferenceCounted(false)
            acquire(12 * 60 * 60 * 1000L)
        }
    }

    private fun releaseWakeLock() {
        wakeLock?.let { if (it.isHeld) it.release() }
        wakeLock = null
    }

    override fun onDestroy() {
        wantOnDuty.set(false)
        pendingRelaunch = null
        NativeBridge.sendOffDuty()
        NativeBridge.setTorDormant(true)
        networkCallback?.let { connectivityManager?.unregisterNetworkCallback(it) }
        releaseWakeLock()
        worker.shutdownNow()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    companion object {
        const val ACTION_START_RESPONDER = "com.bitaid.app.START_RESPONDER"
        const val ACTION_START_CALLER = "com.bitaid.app.START_CALLER"
        const val ACTION_STOP = "com.bitaid.app.STOP"

        const val EXTRA_NAME = "name"
        const val EXTRA_PEER = "peer"
        const val EXTRA_WALLET = "wallet"
        const val EXTRA_POOL = "pool"
        const val EXTRA_SAT_SCALE = "sat_scale"
        const val EXTRA_TIME_SCALE = "time_scale"
        const val EXTRA_HAS_LOC = "has_loc"
        const val EXTRA_LAT = "lat"
        const val EXTRA_LON = "lon"

        private const val CHANNEL_DUTY = "bitaid_duty"
        private const val CHANNEL_ALERT = "bitaid_alert"
        private const val NOTIF_ID = 1001
        private const val ALERT_NOTIF_ID = 1002
        private const val QUICK_FAIL_MS = 10_000L
        private const val MAX_QUICK_FAILS = 3
    }
}
