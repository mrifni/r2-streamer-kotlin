/*
 * Module: r2-streamer-kotlin
 * Developers: Mickaël Menu
 *
 * Copyright (c) 2020. Readium Foundation. All rights reserved.
 * Use of this source code is governed by a BSD-style license which is detailed in the
 * LICENSE file present in the project repository where this source code is maintained.
 */

package org.readium.r2.streamer.fetcher.drm

import org.readium.r2.shared.drm.DRMLicense
import org.readium.r2.shared.publication.Link
import timber.log.Timber
import java.io.IOException
import java.io.InputStream

private const val aesBlockSize = 16  // bytes

/**
 * A DRM input stream to read content encrypted with the CBC algorithm. Supports random access for
 * byte range requests.
 */
internal class CbcDrmInputStream(
    private val inputStream: InputStream,
    private val link: Link,
    private val license: DRMLicense
) : InputStream() {

    private var position: Int = 0

    override fun available(): Int = plainTextSize - position

    override fun read(): Int {
        throw NotImplementedError("read() is not supported for CbcDrmInputStream")
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        try {
            val available = available()
            val length = len.coerceAtMost(available)
            if (length <= 0) {
                return -1  // EOF
            }

            val blockPosition = position % aesBlockSize

            // For beginning of the cipher text, IV used for XOR.
            // For cipher text in the middle, previous block used for XOR.
            val readPosition = position - blockPosition
//             ... skip to readPosition from the start

            // Count blocks to read.
            // First block for IV or previous block to perform XOR.
            var blocksCount = 1
            var bytesInFirstBlock = (aesBlockSize - blockPosition) % aesBlockSize
            if (length < bytesInFirstBlock) {
                bytesInFirstBlock = 0
            }
            if (bytesInFirstBlock > 0) {
                blocksCount += 1
            }

            blocksCount += (length - bytesInFirstBlock) / aesBlockSize
            if ((length - bytesInFirstBlock) % aesBlockSize != 0) {
                blocksCount += 1
            }

            val bytesSize = blocksCount * aesBlockSize
            var bytes = ByteArray(bytesSize)
            val read = inputStream.read(bytes)
            assert(read == bytesSize)

            bytes = license.decipher(bytes)
                ?: throw IOException("Can't decrypt the content at: ${link.href}")

            // TODO: Double check if there is a different way to remove padding from HTML resources only.
            if (link.mediaType?.isHtml == true) {
                // Removes the padding.
                val padding = bytes.last().toInt()
                bytes = bytes.copyOfRange(0, bytes.size - padding)
            }

            if (bytes.size > length) {
                bytes = bytes.copyOfRange(0, length)
            }

            bytes.copyInto(b, destinationOffset = off)

            position += bytes.size

            return bytes.size

        } catch (e: Exception) {
            throw IOException("Failed to read CBC-encrypted stream for: ${link.href}", e)
        }
    }

    private val plainTextSize: Int by lazy {
        try {
            val length = inputStream.available()
            if (length < 2 * aesBlockSize) {
                Timber.e("Invalid CBC-encrypted stream for ${link.href}")
                return@lazy 0
            }

            val readPosition = length - (2 * aesBlockSize)
            val bufferSize = 2 * aesBlockSize
            val buffer = ByteArray(bufferSize)

            inputStream.run {
                skip(readPosition.toLong())
                read(buffer)
            }

            val decryptedData = license.decipher(buffer)
                ?: return@lazy 0

            return@lazy length -
                aesBlockSize -  // Minus IV or previous block
                (aesBlockSize - decryptedData.size) % aesBlockSize  // Minus padding part

        } catch (e: Exception) {
            Timber.e(e, "Failed to get the plain text size of CBC-encrypted stream for ${link.href}")
            return@lazy 0
        }
    }

}