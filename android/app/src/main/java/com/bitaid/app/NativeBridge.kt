package com.bitaid.app

import java.io.IOException

/**
 * Callback invoked synchronously from Rust (`bitaid_node::secrets::SecretStore`).
 * Method names and signatures are matched by `crates/bitaid-jni/src/lib.rs`.
 */
interface SecretStoreCallback {
    /**
     * Returns `null` ONLY when `name` does not exist.
     * Throws `IOException` if the file exists but cannot be read or decrypted.
     */
    @Throws(IOException::class)
    fun get(name: String): ByteArray?
    fun put(name: String, data: ByteArray): Boolean
    fun append(name: String, line: String): Boolean
}

/**
 * Callback invoked from Rust's `bitaid-events` thread with one JSON-encoded event per call.
 */
interface EventCallback {
    fun onEvent(json: String)
}

/**
 * Thin JNI bridge to `libbitaid_jni.so`.
 * The Tor SOCKS secret never crosses this boundary: `startRole` injects `BITAID_SOCKS` inside Rust.
 */
object NativeBridge {
    init {
        System.loadLibrary("bitaid_jni")
    }

    external fun installSecretStore(store: SecretStoreCallback): Boolean
    external fun startTor(stateDir: String, cacheDir: String): String
    external fun stopTor()
    external fun setTorDormant(soft: Boolean)
    external fun torNetworkChanged()

    /** Returns `""` on success or a refusal reason on failure. */
    external fun startRole(
        settingsJson: String,
        argsJson: String,
        listener: EventCallback,
    ): String

    external fun sendRaiseAlert(hasLoc: Boolean, lat: Double, lon: Double)
    external fun sendAccept(caseId: String)
    external fun sendDecline(caseId: String)
    external fun sendVote(
        caseId: String,
        classesJson: String,
        achieved: Boolean,
        misuse: Boolean,
    ): Boolean
    external fun sendOffDuty()
    external fun sendPosition(lat: Double, lon: Double, accuracyM: Float, atEpochSecs: Long)
}
