package com.cftester.scanner.core.engine

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.security.SecureRandom

object WebSocketFrameBuilder {

    fun buildBinaryFrame(payload: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        val length = payload.size

        // Opcode 0x82: FIN bit (0x80) | Binary frame (0x02)
        out.write(0x82)

        // RFC 6455 Client frames MUST have mask bit (0x80) set
        if (length <= 125) {
            out.write(0x80 or length)
        } else if (length <= 65535) {
            out.write(0x80 or 126)
            out.write(ByteBuffer.allocate(2).putShort(length.toShort()).array())
        } else {
            out.write(0x80 or 127)
            out.write(ByteBuffer.allocate(8).putLong(length.toLong()).array())
        }

        // 4-byte masking key
        val maskKey = ByteArray(4)
        SecureRandom().nextBytes(maskKey)
        out.write(maskKey)

        // XOR masked payload
        val masked = ByteArray(length)
        for (i in 0 until length) {
            masked[i] = (payload[i].toInt() xor maskKey[i % 4].toInt()).toByte()
        }
        out.write(masked)

        return out.toByteArray()
    }
}
