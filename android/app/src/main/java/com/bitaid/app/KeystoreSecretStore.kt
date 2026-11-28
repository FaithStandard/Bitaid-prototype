package com.bitaid.app

import android.content.Context
import com.google.crypto.tink.Aead
import com.google.crypto.tink.KeyTemplates
import com.google.crypto.tink.aead.AeadConfig
import com.google.crypto.tink.integration.android.AndroidKeysetManager
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import java.security.SecureRandom

/**
 * M4 step 5: Keystore-backed encrypted secret store using Google Tink (Apache-2.0).
 *
 * - Master key lives in Android Keystore (`android-keystore://bitaid_master_key`) with NO
 *   biometric/user-auth gate so an on-duty responder can accept alerts with the screen off.
 * - Verifies the Keystore alias exists after Tink init; refuses any cleartext fallback.
 * - `get(name)` returns `null` ONLY when the file does not exist; any read/decrypt failure throws
 *   `IOException` so callers never silently mint a replacement identity or link stake.
 * - Every secret blob is encrypted with AES256-GCM using `name` as AAD and written atomically
 *   (temp file + fsync + rename) under `noBackupFilesDir`.
 */
class KeystoreSecretStore(context: Context) : SecretStoreCallback {

    private val dir: File = File(context.noBackupFilesDir, "bitaid-secrets").apply { mkdirs() }
    private val aead: Aead
    private val lock = Any()

    init {
        AeadConfig.register()
        val manager = AndroidKeysetManager.Builder()
            .withSharedPref(context, KEYSET_NAME, PREF_FILE)
            .withKeyTemplate(KeyTemplates.get("AES256_GCM"))
            .withMasterKeyUri(MASTER_KEY_URI)
            .build()
        // Confirm the master key actually lives in AndroidKeyStore (no cleartext fallback).
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (!ks.containsAlias(MASTER_KEY_ALIAS)) {
            throw IOException("AndroidKeyStore master key alias missing; refusing cleartext keyset")
        }
        aead = manager.keysetHandle.getPrimitive(Aead::class.java)
    }

    private fun safeFile(name: String): File {
        if (name.isEmpty() || name.contains('/') || name.contains('\\') || name.contains("..")) {
            throw IOException("Invalid secret name: $name")
        }
        return File(dir, "$name.enc")
    }

    @Throws(IOException::class)
    override fun get(name: String): ByteArray? = synchronized(lock) {
        val file = safeFile(name)
        if (!file.exists()) return null
        return try {
            val ct = file.readBytes()
            aead.decrypt(ct, name.toByteArray(StandardCharsets.UTF_8))
        } catch (e: Exception) {
            throw IOException("Failed to read or decrypt secret '$name': ${e.message}", e)
        }
    }

    override fun put(name: String, data: ByteArray): Boolean = synchronized(lock) {
        val file = try {
            safeFile(name)
        } catch (_: IOException) {
            return false
        }
        return writeAtomic(file, name, data)
    }

    override fun append(name: String, line: String): Boolean = synchronized(lock) {
        val file = try {
            safeFile(name)
        } catch (_: IOException) {
            return false
        }
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
     * Returns the node's 32-byte hex identity secret (passed in memory via `--secret`).
     * Mints a new key ONLY when the file does not exist; throws `IOException` on decrypt failure
     * so an existing identity is never silently orphaned.
     */
    @Throws(IOException::class)
    fun getOrCreateIdentityHex(roleName: String): String = synchronized(lock) {
        val keyName = "identity-$roleName.hex"
        val existing = get(keyName) // throws IOException if present but unreadable
        if (existing != null) {
            val s = String(existing, StandardCharsets.UTF_8).trim()
            if (s.length == 64) return s
            throw IOException("Stored identity '$keyName' is malformed")
        }
        val raw = ByteArray(32)
        SecureRandom().nextBytes(raw)
        val hex = raw.joinToString("") { "%02x".format(it) }
        if (!put(keyName, hex.toByteArray(StandardCharsets.UTF_8))) {
            throw IOException("Failed to persist new identity '$keyName'")
        }
        return hex
    }

    @Throws(IOException::class)
    fun getRpcUrl(): String {
        val bytes = get(RPC_URL_NAME) ?: return ""
        return String(bytes, StandardCharsets.UTF_8).trim()
    }

    fun putRpcUrl(url: String): Boolean {
        return put(RPC_URL_NAME, url.trim().toByteArray(StandardCharsets.UTF_8))
    }

    companion object {
        private const val KEYSET_NAME = "bitaid_secret_store_keyset"
        private const val PREF_FILE = "bitaid_tink_prefs"
        private const val MASTER_KEY_ALIAS = "bitaid_master_key"
        private const val MASTER_KEY_URI = "android-keystore://$MASTER_KEY_ALIAS"
        private const val RPC_URL_NAME = "rpc_url.txt"
    }
}
