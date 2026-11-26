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
import java.util.concurrent.atomic.AtomicBoolean

/**
 * M4 step 4: Foreground service keeping Arti Tor and the active role alive with screen off.
 *
 * - Declares `specialUse` while on duty (and adds `location` when granted).
 * - Filters `ConnectivityManager.NetworkCallback` by `Network.networkHandle` so
 *   `NativeBridge.torNetworkChanged()` runs ONLY when the default network actually switches.
 * - Calls `NativeBridge.setTorDormant(false/true)` on duty transitions.
 * - Never leaves the UI showing "on duty" after a `Fatal` event.
 */
class BitaidService : Service() {

    private val worker = Executors.newSingleThreadExecutor()
    private val wantOnDuty = AtomicBoolean(false)

    private var secretStore: KeystoreSecretStore? = null
    private var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var activeNetworkHandle: Long? = null
    private var wakeLock: PowerManager.WakeLock? = null
    private var currentRole: String = "responder"
    private var lastConfig: RoleLaunchConfig? = null

    data class RoleLaunchConfig(
        val role: String,
        val nodeName: String,
        val peerOnion: String,
        val rpcUrl: String,
        val wallet: String,
        val lat: Double,
        val lon: Double,
    )

    override fun onCreate() {
        super.onCreate()
        createChannels()
        val store = KeystoreSecretStore(applicationContext)
        secretStore = store
        NativeBridge.installSecretStore(store)
        registerFilteredNetworkCallback()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START_RESPONDER, ACTION_START_CALLER -> {
                val role = if (intent.action == ACTION_START_CALLER) "caller" else "responder"
                val cfg = RoleLaunchConfig(
                    role = role,
                    nodeName = intent.getStringExtra(EXTRA_NAME) ?: role,
                    peerOnion = intent.getStringExtra(EXTRA_PEER) ?: "",
                    rpcUrl = intent.getStringExtra(EXTRA_RPC) ?: "",
                    wallet = intent.getStringExtra(EXTRA_WALLET) ?: "w",
                    lat = intent.getDoubleExtra(EXTRA_LAT, 13.6929),
                    lon = intent.getDoubleExtra(EXTRA_LON, -89.2182),
                )
                currentRole = role
                lastConfig = cfg
                wantOnDuty.set(true)
                promoteForeground("Starting Tor ($role)...")
                acquireWakeLock()
                worker.execute { startTorAndRole(cfg) }
            }
            ACTION_STOP -> {
                wantOnDuty.set(false)
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
            wantOnDuty.set(false)
            BitaidState.update {
                it.copy(status = ServiceStatus.FAULT, statusDetail = "Tor failed: $err")
            }
            updateNotification("Tor failed: $err")
            releaseWakeLock()
            stopSelf()
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
        val store = secretStore ?: return
        val identityHex = store.getOrCreateIdentityHex(cfg.nodeName)

        val settings = JSONObject().apply {
            put("HOME", filesDir.absolutePath)
            put("BITAID_RPC", cfg.rpcUrl)
            put("BITAID_WALLET", cfg.wallet)
            put("BITAID_REPLY_MIN", "900")
            put("BITAID_TIME_SCALE", "1")
        }

        val args = JSONArray().apply {
            put("bitaid-node")
            put("--role"); put(cfg.role)
            put("--name"); put(cfg.nodeName)
            put("--secret"); put(identityHex)
            if (cfg.peerOnion.isNotBlank()) {
                put("--peer"); put(cfg.peerOnion)
            }
            put("--lat"); put(cfg.lat.toString())
            put("--lon"); put(cfg.lon.toString())
            if (cfg.role == "responder") {
                put("--ask-accept")
                put("--ask-vote")
            } else {
                put("--ask-alert")
            }
        }

        BitaidState.update {
            it.copy(
                status = if (cfg.role == "responder") ServiceStatus.ON_DUTY else ServiceStatus.BOOTSTRAPPING_TOR,
                statusDetail = if (cfg.role == "responder") "On duty — listening for alerts" else "Preparing caller...",
            )
        }
        updateNotification(if (cfg.role == "responder") "On duty — listening for alerts" else "Caller active")

        val started = NativeBridge.startRole(
            settings.toString(),
            args.toString(),
            object : EventCallback {
                override fun onEvent(json: String) {
                    val type = BitaidState.applyNativeEvent(json)
                    when (type) {
                        "Alert" -> postAlertNotification()
                        "Location" -> updateNotification("Responding — location verified")
                        "Fatal" -> {
                            wantOnDuty.set(false)
                            updateNotification("Node fault — stopped")
                            releaseWakeLock()
                            stopSelf()
                        }
                        "RoleExited" -> {
                            if (wantOnDuty.get() && cfg.role == "responder" && BitaidState.snapshot.status != ServiceStatus.FAULT) {
                                // Case completed cleanly; loop to listen for next alert.
                                worker.execute { launchRole(cfg) }
                            } else {
                                finishOffDuty()
                            }
                        }
                    }
                }
            },
        )
        if (!started) {
            wantOnDuty.set(false)
            BitaidState.update {
                it.copy(status = ServiceStatus.FAULT, statusDetail = "Failed to start role (already running?)")
            }
            releaseWakeLock()
            stopSelf()
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

    /**
     * Filters Android's default-network callback by `networkHandle` so `torNetworkChanged()` is
     * only invoked when the active default network genuinely switches (e.g. Wi-Fi <-> cellular),
     * not on initial registration or secondary-network / capability churn.
     */
    private fun registerFilteredNetworkCallback() {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        connectivityManager = cm
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                val handle = network.networkHandle
                val prev = activeNetworkHandle
                activeNetworkHandle = handle
                if (prev != null && prev != handle && wantOnDuty.get()) {
                    worker.execute { NativeBridge.torNetworkChanged() }
                }
            }

            override fun onLost(network: Network) {
                if (activeNetworkHandle == network.networkHandle) {
                    activeNetworkHandle = null
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
        const val EXTRA_RPC = "rpc"
        const val EXTRA_WALLET = "wallet"
        const val EXTRA_LAT = "lat"
        const val EXTRA_LON = "lon"

        private const val CHANNEL_DUTY = "bitaid_duty"
        private const val CHANNEL_ALERT = "bitaid_alert"
        private const val NOTIF_ID = 1001
        private const val ALERT_NOTIF_ID = 1002
    }
}
