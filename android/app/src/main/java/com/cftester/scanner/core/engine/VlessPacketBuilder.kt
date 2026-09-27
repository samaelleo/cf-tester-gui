package com.cftester.scanner.core.engine

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.UUID

object VlessPacketBuilder {

    fun build(
        userUuid: String,
        targetHost: String = "connectivitycheck.gstatic.com",
        targetPort: Int = 80,
        httpPath: String = "/generate_204"
    ): ByteArray {
        val uuidBytes = try {
            val u = UUID.fromString(userUuid.trim())
            val bb = ByteBuffer.wrap(ByteArray(16))
            bb.putLong(u.mostSignificantBits)
            bb.putLong(u.leastSignificantBits)
            bb.array()
        } catch (_: Exception) {
            val randomBytes = ByteArray(16)
            SecureRandom().nextBytes(randomBytes)
            randomBytes
        }

        val hostBytes = targetHost.toByteArray(Charsets.US_ASCII)
        val portBytes = ByteBuffer.allocate(2).putShort(targetPort.toShort()).array()

        val out = ByteArrayOutputStream()

        // VLESS Request Header:
        // Version (1 byte): 0x00
        out.write(0x00)
        // UUID (16 bytes)
        out.write(uuidBytes)
        // Addons length (1 byte): 0x00
        out.write(0x00)
        // Command (1 byte): 0x01 (TCP Connect)
        out.write(0x01)
        // Target Port (2 bytes): Big-endian
        out.write(portBytes)
        // Address Type (1 byte): 0x02 (Domain Name)
        out.write(0x02)
        // Address Length (1 byte)
        out.write(hostBytes.size and 0xFF)
        // Address (N bytes)
        out.write(hostBytes)

        // Payload: HTTP/1.1 GET generate_204 to target host
        val httpReq = (
            "GET $httpPath HTTP/1.1\r\n" +
            "Host: $targetHost\r\n" +
            "User-Agent: Mozilla/5.0 (Android; Mobile)\r\n" +
            "Connection: close\r\n\r\n"
        ).toByteArray(Charsets.US_ASCII)

        out.write(httpReq)
        return out.toByteArray()
    }
}
