package io.github.rhythmcache.adb

import io.github.rhythmcache.adb.pairing.PairingIdentity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okio.BufferedSink
import okio.BufferedSource
import okio.buffer
import okio.sink
import okio.source
import org.bouncycastle.crypto.params.AsymmetricKeyParameter
import org.bouncycastle.crypto.util.PrivateKeyFactory
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.tls.Certificate
import org.bouncycastle.tls.CertificateRequest
import org.bouncycastle.tls.DefaultTlsClient
import org.bouncycastle.tls.ProtocolVersion
import org.bouncycastle.tls.SignatureAndHashAlgorithm
import org.bouncycastle.tls.TlsAuthentication
import org.bouncycastle.tls.TlsClientContext
import org.bouncycastle.tls.TlsClientProtocol
import org.bouncycastle.tls.TlsCredentials
import org.bouncycastle.tls.TlsProtocol
import org.bouncycastle.tls.TlsServerCertificate
import org.bouncycastle.tls.crypto.TlsCertificate
import org.bouncycastle.tls.crypto.TlsCrypto
import org.bouncycastle.tls.crypto.TlsCryptoParameters
import org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedSigner
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom
import org.bouncycastle.asn1.x509.Certificate as ASN1Certificate

/**
 * ADB TLS transport (Android 11+). Pins the peer certificate learned during
 * pairing rather than accepting anything -- pairing's "accept any cert" is
 * only safe because SPAKE2 authenticates on top of it; this connection has
 * no such secondary layer, so fingerprint match is the only thing standing
 * between this and a MITM.
 *
 * Reuses the exact same AdbPacket/BufferedSource/BufferedSink plumbing as
 * TcpPacketTransport -- the only thing that differs between the two
 * transports is how the underlying byte stream is produced. Packet framing,
 * checksums, and parsing are untouched and unduplicated.
 *
 * Protocol note: on a TLS transport connection, adbd does not send an AUTH
 * packet -- identity is already proven by the pinned certificate, so the
 * handshake goes straight to CNXN. AdbConnection's existing AUTH handling
 * simply never triggers on this transport; no special-casing needed.
 */
class TlsPacketTransport private constructor(
    private val socket: Socket,
    private val protocol: TlsProtocol,
    private val source: BufferedSource,
    private val sink: BufferedSink,
) : PacketTransport {
    companion object {
        private val secureRandom = SecureRandom()
        private val sharedCrypto: TlsCrypto = BcTlsCrypto(secureRandom)

        suspend fun connect(
            host: String,
            port: Int,
            identity: PairingIdentity,
        ): TlsPacketTransport =
            withContext(Dispatchers.IO) {
                val socket = Socket()
                try {
                    // The same endpoint is subsequently reused for the A_STLS
                    // upgrade. A bounded connect avoids hanging the UI workflow.
                    socket.connect(InetSocketAddress(host, port), CONNECT_TIMEOUT_MS)
                    socket.tcpNoDelay = true
                    // Bound the plaintext A_STLS probe and TLS negotiation too.
                    socket.soTimeout = HANDSHAKE_READ_TIMEOUT_MS

                    val crypto: TlsCrypto = sharedCrypto
                val (certChain, privKey) = parseIdentity(crypto, identity.certPem, identity.privateKeyPem)

                var capturedContext: TlsClientContext? = null

                val client =
                    object : DefaultTlsClient(crypto) {
                        override fun getSupportedVersions(): Array<ProtocolVersion> = arrayOf(ProtocolVersion.TLSv13)

                        override fun init(context: TlsClientContext) {
                            capturedContext = context
                            super.init(context)
                        }

                        override fun getAuthentication(): TlsAuthentication =
                            object : TlsAuthentication {
                                override fun notifyServerCertificate(serverCertificate: TlsServerCertificate) {
                                    // Accept the device's self-signed TLS server certificate.
                                    // In Android ADB Wireless Debugging, mutual authentication is established at the ADB protocol
                                    // layer via RSA key challenge (ADB AUTH), rather than X.509 CA validation or cert pinning.
                                }

                                override fun getClientCredentials(certificateRequest: CertificateRequest): TlsCredentials =
                                    BcDefaultTlsCredentialedSigner(
                                        TlsCryptoParameters(requireNotNull(capturedContext)),
                                        crypto as BcTlsCrypto,
                                        privKey,
                                        certChain,
                                        SignatureAndHashAlgorithm.rsa_pss_rsae_sha256,
                                    )
                            }
                    }

                // first we here perform a plaintext A_STLS protocol upgrade handshake.
                // as per AOSP protocol.txt / transport.cpp: adbd sends A_STLS as the
                // unsolicited first packet on a wireless debugging TLS connection (this
                // replaces the immediate CNXN that a plain TCP transport would otherwise
                // see first). The client must read it, echo back an A_STLS with the
                // SAME version the device sent, and only then proceed to the TLS handshake.
                val rawInput = socket.getInputStream()
                val rawOutput = socket.getOutputStream()

                // Send initial plaintext A_CNXN packet to the server to trigger the A_STLS response.
                val clientCnxn =
                    AdbPacket(
                        command = AdbCmd.CNXN,
                        arg0 = ADB_VERSION,
                        arg1 = MAX_PAYLOAD,
                        payload = HOST_FEATURES_BYTES,
                    )
                val cnxnBuffer = okio.Buffer()
                clientCnxn.writeTo(cnxnBuffer)
                rawOutput.write(cnxnBuffer.readByteArray())
                rawOutput.flush()

                val headerBytes = ByteArray(24)
                var bytesRead = 0
                while (bytesRead < 24) {
                    val r = rawInput.read(headerBytes, bytesRead, 24 - bytesRead)
                    if (r == -1) throw AdbException.Transport("EOF reached while reading A_STLS header", null)
                    bytesRead += r
                }

                val command =
                    (headerBytes[0].toInt() and 0xFF) or
                        ((headerBytes[1].toInt() and 0xFF) shl 8) or
                        ((headerBytes[2].toInt() and 0xFF) shl 16) or
                        ((headerBytes[3].toInt() and 0xFF) shl 24)

                val deviceStlsVersion =
                    (headerBytes[4].toInt() and 0xFF) or
                        ((headerBytes[5].toInt() and 0xFF) shl 8) or
                        ((headerBytes[6].toInt() and 0xFF) shl 16) or
                        ((headerBytes[7].toInt() and 0xFF) shl 24)

                if (command != AdbCmd.STLS) {
                    throw AdbException.Protocol(
                        "Expected A_STLS command (0x${AdbCmd.STLS.toString(16)}) from device, got: 0x${command.toString(16)}",
                    )
                }

                // Echo the SAME version the device sent -- do not hardcode a constant here.
                val clientStls =
                    AdbPacket(
                        command = AdbCmd.STLS,
                        arg0 = deviceStlsVersion,
                        arg1 = 0,
                        payload = ByteArray(0),
                    )
                val buffer = okio.Buffer()
                clientStls.writeTo(buffer)
                rawOutput.write(buffer.readByteArray())
                rawOutput.flush()

                // here we now proceed with the actual TLS 1.3 handshake over the same upgraded streams.
                val protocol = TlsClientProtocol(rawInput, rawOutput)

                try {
                    protocol.connect(client) // blocks until handshake completes or throws
                } catch (e: org.bouncycastle.tls.TlsFatalAlert) {
                    runCatching { protocol.close() }
                    runCatching { socket.close() }
                    if (isCertRejectionAlert(e.alertDescription)) {
                        throw AdbException.NotPaired(cause = e)
                    }
                    throw AdbException.Transport("TLS handshake failed", e)
                } catch (e: Exception) {
                    runCatching { protocol.close() }
                    runCatching { socket.close() }
                    throw AdbException.Transport("TLS handshake failed", e)
                }

                // Once TLS is established, keep the connection alive during
                // normal idle periods; the timeout above is only for setup.
                socket.soTimeout = 0
                val source = protocol.inputStream.source().buffer()
                val sink = protocol.outputStream.sink().buffer()

                TlsPacketTransport(socket, protocol, source, sink)
                } catch (e: Exception) {
                    // Also close on failures before TLS protocol.connect(), such
                    // as a classic ADB CNXN response instead of A_STLS. This is
                    // the expected probe failure on Android 7.x TCP adbd.
                    runCatching { socket.close() }
                    throw e
                }
            }

        private const val CONNECT_TIMEOUT_MS = 10_000
        private const val HANDSHAKE_READ_TIMEOUT_MS = 10_000

        private fun isCertRejectionAlert(desc: Short): Boolean =
            when (desc) {
                org.bouncycastle.tls.AlertDescription.bad_certificate,
                org.bouncycastle.tls.AlertDescription.certificate_unknown,
                org.bouncycastle.tls.AlertDescription.unknown_ca,
                org.bouncycastle.tls.AlertDescription.access_denied,
                -> true
                else -> false
            }

        private fun parseIdentity(
            crypto: TlsCrypto,
            certPem: String,
            privateKeyPem: String,
        ): Pair<Certificate, AsymmetricKeyParameter> {
            val certHolder =
                PEMParser(java.io.StringReader(certPem)).readObject()
                    as org.bouncycastle.cert.X509CertificateHolder
            val asn1Cert = ASN1Certificate.getInstance(certHolder.encoded)
            val tlsCert: TlsCertificate = crypto.createCertificate(asn1Cert.encoded)
            val certChain = Certificate(ByteArray(0), arrayOf(org.bouncycastle.tls.CertificateEntry(tlsCert, null)))

            val keyObj = PEMParser(java.io.StringReader(privateKeyPem)).readObject()
            val privKey =
                when (keyObj) {
                    is org.bouncycastle.asn1.pkcs.PrivateKeyInfo -> PrivateKeyFactory.createKey(keyObj)
                    is org.bouncycastle.openssl.PEMKeyPair -> PrivateKeyFactory.createKey(keyObj.privateKeyInfo)
                    else -> error("Unsupported private key PEM format: ${keyObj?.javaClass}")
                }

            return certChain to privKey
        }
    }

    private val writeLock = Any()

    override fun send(pkt: AdbPacket) {
        synchronized(writeLock) {
            pkt.writeTo(sink)
        }
    }

    override fun recv(): AdbPacket {
        try {
            return AdbPacket.readFrom(source)
        } catch (e: AdbException.Transport) {
            val alertDesc = findTlsFatalAlert(e)
            if (alertDesc != null && isCertRejectionAlert(alertDesc)) {
                throw AdbException.NotPaired(cause = e)
            }
            throw e
        }
    }

    private fun findTlsFatalAlert(e: Throwable): Short? {
        var cur: Throwable? = e
        while (cur != null) {
            when (cur) {
                is org.bouncycastle.tls.TlsFatalAlertReceived -> return cur.alertDescription
                is org.bouncycastle.tls.TlsFatalAlert -> return cur.alertDescription
            }
            cur = cur.cause
        }
        return null
    }

    override fun close() {
        runCatching { source.close() }
        runCatching { sink.close() }
        runCatching { protocol.close() }
        runCatching { socket.close() }
    }
}
