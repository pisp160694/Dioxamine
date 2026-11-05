package io.github.rhythmcache.adb

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okio.BufferedSink
import okio.BufferedSource
import okio.buffer
import okio.sink
import okio.source
import java.net.InetSocketAddress
import java.net.Socket

class TcpPacketTransport private constructor(
    private val socket: Socket,
    private val source: BufferedSource,
    private val sink: BufferedSink,
) : PacketTransport {
    companion object {
        suspend fun connect(
            host: String,
            port: Int = 5555,
        ): TcpPacketTransport =
            withContext(Dispatchers.IO) {
                val socket = Socket()
                try {
                    // Bound connection establishment so an unreachable TV cannot
                    // leave the connection coroutine waiting indefinitely.
                    socket.connect(InetSocketAddress(host, port), CONNECT_TIMEOUT_MS)
                    socket.tcpNoDelay = true
                    val source = socket.source().buffer()
                    val sink = socket.sink().buffer()
                    TcpPacketTransport(socket, source, sink)
                } catch (e: Exception) {
                    runCatching { socket.close() }
                    throw e
                }
            }

        private const val CONNECT_TIMEOUT_MS = 10_000
    }

    private val writeLock = Any()

    override fun send(pkt: AdbPacket) {
        synchronized(writeLock) {
            pkt.writeTo(sink)
        }
    }

    override fun recv(): AdbPacket = AdbPacket.readFrom(source)

    override fun close() {
        runCatching { source.close() }
        runCatching { sink.close() }
        runCatching { socket.close() }
    }
}
