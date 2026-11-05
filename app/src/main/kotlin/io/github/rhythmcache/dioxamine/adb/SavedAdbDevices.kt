package io.github.rhythmcache.dioxamine.adb

import android.content.Context

/** Persistent list of TCP/TLS devices ("ip:port") to restore on app start. */
object SavedAdbDevices {
    private const val PREFS_NAME = "adb_saved_devices"
    private const val KEY = "devices"
    private const val DELIM = "|"

    private fun prefs(c: Context) = c.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    fun getAll(c: Context): List<String> =
        prefs(c).getString(KEY, null)?.split(DELIM)?.filter { it.isNotBlank() } ?: emptyList()

    fun add(c: Context, address: String) {
        val a = address.trim()
        if (a.isEmpty()) return
        val cur = getAll(c)
        if (a in cur) return
        prefs(c).edit().putString(KEY, (cur + a).joinToString(DELIM)).apply()
    }

    fun remove(c: Context, address: String) {
        val cur = getAll(c)
        if (address !in cur) return
        prefs(c).edit().putString(KEY, (cur - address).joinToString(DELIM)).apply()
    }
}
