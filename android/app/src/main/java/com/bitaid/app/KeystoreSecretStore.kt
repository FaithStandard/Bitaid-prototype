package com.bitaid.app

import android.content.Context
import com.google.crypto.tink.Aead
import com.google.crypto.tink.KeyTemplates
import com.google.crypto.tink.aead.AeadConfig
import com.google.crypto.tink.integration.android.AndroidKeysetManager
import java.io.File
import java.io.FileOutputStream
import java.nio.charset.StandardCharsets
import java.security.SecureRandom

/**
 * M4 step 5: Keystore-backed encrypted secret store using Google Tink (Apache-2.0).
 *
 * - Master key lives in Android Keystore (`android-keystore://bitaid_master_key`) with NO
 *   biometric/user-auth gate so an on-duty responder can accept alerts with the screen off.
 * - Every secret blob is encrypted with AES256-GCM using `name` as AAD (prevents file-swap
 *   attacks) and written atomically (temp file + fsync + rename) under `noBackupFilesDir`.
 * - No plaintext secret ever touches flash.
 */
class KeystoreSecretStore(context: Context) : SecretStoreCallback {

    private val dir: File = File(context.noBackupFilesDir, "bitaid-secrets").apply { mkdirs() }
    private val aead: Aead
    private val lock = Any()

    init {
        AeadConfig.register()
        val handle = AndroidKeysetManager.Builder()
            .withSharedPref(context, KEYSET_NAME, PREF_FILE)
            .withKeyTemplate(KeyTemplates.get("AES256_GCM"))
            .withMasterKeyUri(MASTER_KEY_URI)
            .build()
            .keysetHandle
        aead = handle.getPrimitive(Aead::class.java)
    }

    private fun safeFile(name: String): File? {
        if (name.isEmpty() || name.contains('/') || name.contains('\\') || name.contains("..")) {
            return null
        }
        return File(dir, "$name.enc")
    }

    override fun get(name: String): ByteArray? = synchronized(lock) {
        val file = safeFile(name) ?: return null
        if (!file.exists()) return null
        return try {
            val ct = file.readBytes()
            aead.decrypt(ct, name.toByteArray(StandardCharsets.UTF_8))
        } catch (_: Exception) {
            null
        }
    }

    override fun put(name: String, data: ByteArray): Boolean = synchronized(lock) {
        val file = safeFile(name) ?: return false
        return writeAtomic(file, name, data)
    }

    override fun append(name: String, line: String): Boolean = synchronized(lock) {
        val file = safeFile(name) ?: return false
        val existing = if (file.exists()) {
            try {
                aead.decrypt(file.readBytes(), name.toByteArray(StandardCharsets.UTF_8))
            } catch (_: Exception) {
                return false
            }
        } else {
            ByteArray(0)
        }
        val lineBytes = line.toByteArray(StandardCharsets.UTF_8)
        val combined = ByteArray(existing.size + lineBytes.size)
        System.arraycopy(existing, 0, combined, 0, existing.size)
        System.arraycopy(lineBytes, 0, combined, existing.size, lineBytes.size)
        return writeAtomic(file, name, combined)
    }

    private fun writeAtomic(target: File, name: String, plaintext: ByteArray): Boolean {
        val tmp = File(dir, "${target.name}.tmp")
        return try {
            val ct = aead.encrypt(plaintext, name.toByteArray(StandardCharsets.UTF_8))
            FileOutputStream(tmp).use { fos ->
                fos.write(ct)
                fos.fd.sync()
            }
            if (!tmp.renameTo(target)) {
                tmp.delete()
                false
            } else {
                true
            }
        } catch (_: Exception) {
            tmp.delete()
            false
        }
    }

    /**
     * Returns the node's 32-byte hex identity secret (passed in memory via `--secret`), generating
     * and storing it encrypted on first launch. Never written to disk in plaintext.
     */
    fun getOrCreateIdentityHex(roleName: String): String = synchronized(lock) {
        val keyName = "identity-$roleName.hex"
        get(keyName)?.let { bytes ->
            val s = String(bytes, StandardCharsets.UTF_8).trim()
            if (s.length == 64) return s
        }
        val raw = ByteArray(32)
        SecureRandom().nextBytes(raw)
        val hex = raw.joinToString("") { "%02x".format(it) }
        put(keyName, hex.toByteArray(StandardCharsets.UTF_8))
        return hex
    }

    companion object {
        private const val KEYSET_NAME = "bitaid_secret_store_keyset"
        private const val PREF_FILE = "bitaid_tink_prefs"
        private const val MASTER_KEY_URI = "android-keystore://bitaid_master_key"
    }
}
