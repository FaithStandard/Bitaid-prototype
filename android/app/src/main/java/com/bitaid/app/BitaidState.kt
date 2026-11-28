package com.bitaid.app

import org.json.JSONObject
import java.util.concurrent.CopyOnWriteArrayList

enum class ServiceStatus {
    OFF_DUTY,
    BOOTSTRAPPING_TOR,
    CONNECTING,
    ON_DUTY,
    CALLER_READY,
    ACTIVE_CASE,
    FAULT,
}

data class AlertPrompt(
    val caseId: String,
    val cell: String,
    val deposit: Long,
    val reward: Long,
    val bounty: Long,
    val distanceM: Int? = null,
    val positionAgeSecs: Long? = null,
)

data class VerifiedLocation(
    val caseId: String,
    val lat: Double,
    val lon: Double,
)

data class BallotPrompt(
    val caseId: String,
    val seats: Int,
    val mySeat: Int,
    val remainingBlocks: Int = 0,
    val remainingSecs: Long = 0L,
    val receivedAtMs: Long = System.currentTimeMillis(),
)

data class CheckLine(
    val node: String,
    val what: String,
    val ok: Boolean,
    val detail: String,
)

data class AppSnapshot(
    val status: ServiceStatus = ServiceStatus.OFF_DUTY,
    val statusDetail: String = "Off duty",
    val lastProgress: String = "",
    val warning: String? = null,
    val alert: AlertPrompt? = null,
    val location: VerifiedLocation? = null,
    val ballotDue: BallotPrompt? = null,
    val passed: Int = 0,
    val failed: Int = 0,
    val checks: List<CheckLine> = emptyList(),
    val logs: List<String> = emptyList(),
)

/**
 * In-process observable state shared between `BitaidService` and `MainActivity`.
 */
object BitaidState {
    private const val MAX_CHECKS = 200
    private const val MAX_LOGS = 200

    private val lock = Any()
    private val listeners = CopyOnWriteArrayList<(AppSnapshot) -> Unit>()

    @Volatile
    private var acceptedAtMs: Long = 0L

    @Volatile
    var snapshot: AppSnapshot = AppSnapshot()
        private set

    fun addListener(l: (AppSnapshot) -> Unit) {
        listeners.add(l)
        l(snapshot)
    }

    fun removeListener(l: (AppSnapshot) -> Unit) {
        listeners.remove(l)
    }

    fun markAcceptedNow() {
        acceptedAtMs = System.currentTimeMillis()
    }

    fun update(transform: (AppSnapshot) -> AppSnapshot) {
        val next = synchronized(lock) {
            snapshot = transform(snapshot)
            snapshot
        }
        for (l in listeners) {
            l(next)
        }
    }

    fun applyNativeEvent(json: String): String {
        val obj = try {
            JSONObject(json)
        } catch (_: Exception) {
            return ""
        }
        val type = obj.optString("type", "")
        update { cur ->
            when (type) {
                "Log" -> {
                    val node = obj.optString("node")
                    val text = obj.optString("text")
                    val line = if (node.isEmpty()) text else "[$node] $text"
                    cur.copy(
                        lastProgress = text,
                        logs = (cur.logs + line).takeLast(MAX_LOGS),
                    )
                }
                "Check" -> {
                    val c = CheckLine(
                        node = obj.optString("node"),
                        what = obj.optString("what"),
                        ok = obj.optBoolean("ok"),
                        detail = obj.optString("detail"),
                    )
                    cur.copy(
                        passed = cur.passed + if (c.ok) 1 else 0,
                        failed = cur.failed + if (c.ok) 0 else 1,
                        checks = (cur.checks + c).takeLast(MAX_CHECKS),
                    )
                }
                "Summary" -> {
                    val p = obj.optInt("passed")
                    val f = obj.optInt("failed")
                    val line = "[${obj.optString("node")}] summary: $p passed, $f failed"
                    cur.copy(
                        passed = p,
                        failed = f,
                        logs = (cur.logs + line).takeLast(MAX_LOGS),
                    )
                }
                "Fatal" -> {
                    val text = obj.optString("text")
                    cur.copy(
                        status = ServiceStatus.FAULT,
                        statusDetail = "FATAL: $text",
                        alert = null,
                        ballotDue = null,
                        logs = (cur.logs + "[FATAL] $text").takeLast(MAX_LOGS),
                    )
                }
                "Warning" -> {
                    val text = obj.optString("text")
                    cur.copy(
                        warning = text,
                        logs = (cur.logs + "[WARN] $text").takeLast(MAX_LOGS),
                    )
                }
                "Listening" -> {
                    val home = obj.optString("home")
                    val cells = obj.optInt("cells")
                    cur.copy(
                        status = ServiceStatus.ON_DUTY,
                        statusDetail = "On duty — listening on $cells cells ($home)",
                    )
                }
                "Alert" -> {
                    val dist = if (obj.has("distance_m") && !obj.isNull("distance_m")) obj.optInt("distance_m") else null
                    val posAge = if (obj.has("position_age_secs") && !obj.isNull("position_age_secs")) obj.optLong("position_age_secs") else null
                    cur.copy(
                        alert = AlertPrompt(
                            caseId = obj.optString("case"),
                            cell = obj.optString("cell"),
                            deposit = obj.optLong("deposit"),
                            reward = obj.optLong("reward"),
                            bounty = obj.optLong("bounty"),
                            distanceM = dist,
                            positionAgeSecs = posAge,
                        )
                    )
                }
                "AutoAccepted" -> {
                    markAcceptedNow()
                    val distM = obj.optInt("max_distance_m", 0)
                    val caseId = obj.optString("case")
                    val line = "[app] Auto-accepted alert ${caseId.take(8)} (within $distM m)"
                    cur.copy(
                        status = ServiceStatus.ACTIVE_CASE,
                        statusDetail = "Accepted automatically (within $distM m) — waiting for exact location",
                        alert = null,
                        logs = (cur.logs + line).takeLast(MAX_LOGS),
                    )
                }
                "Location" -> {
                    val dt = if (acceptedAtMs > 0L) {
                        val s = (System.currentTimeMillis() - acceptedAtMs) / 1000.0
                        " (%.1f s after accept)".format(s)
                    } else {
                        ""
                    }
                    val locLine = "[app] Verified location arrived$dt"
                    cur.copy(
                        status = ServiceStatus.ACTIVE_CASE,
                        statusDetail = "Responding — location verified$dt",
                        location = VerifiedLocation(
                            caseId = obj.optString("case"),
                            lat = obj.optDouble("lat"),
                            lon = obj.optDouble("lon"),
                        ),
                        logs = (cur.logs + locLine).takeLast(MAX_LOGS),
                    )
                }
                "BallotDue" -> {
                    cur.copy(
                        ballotDue = BallotPrompt(
                            caseId = obj.optString("case"),
                            seats = obj.optInt("seats"),
                            mySeat = obj.optInt("my_seat"),
                            remainingBlocks = obj.optInt("remaining_blocks", 0),
                            remainingSecs = obj.optLong("remaining_secs", 0L),
                            receivedAtMs = System.currentTimeMillis(),
                        )
                    )
                }
                "BallotTick" -> {
                    val tickCase = obj.optString("case")
                    val bp = cur.ballotDue
                    if (bp != null && bp.caseId == tickCase) {
                        cur.copy(
                            ballotDue = bp.copy(
                                remainingBlocks = obj.optInt("remaining_blocks", bp.remainingBlocks),
                                remainingSecs = obj.optLong("remaining_secs", bp.remainingSecs),
                                receivedAtMs = System.currentTimeMillis(),
                            )
                        )
                    } else {
                        cur
                    }
                }
                "BallotClosed" -> {
                    val closedCase = obj.optString("case")
                    val keep = cur.ballotDue?.takeIf { it.caseId != closedCase }
                    val line = "[app] Ballot window closed for ${closedCase.take(8)}"
                    cur.copy(
                        ballotDue = keep,
                        logs = (cur.logs + line).takeLast(MAX_LOGS),
                    )
                }
                "ReadyToAlert" -> {
                    cur.copy(
                        status = ServiceStatus.CALLER_READY,
                        statusDetail = "Caller ready — press SOS to alert",
                    )
                }
                "RoleExited" -> {
                    val code = obj.optInt("code")
                    val line = "[app] role exited with code $code"
                    cur.copy(
                        alert = null,
                        ballotDue = null,
                        logs = (cur.logs + line).takeLast(MAX_LOGS),
                    )
                }
                else -> cur
            }
        }
        return type
    }
}
