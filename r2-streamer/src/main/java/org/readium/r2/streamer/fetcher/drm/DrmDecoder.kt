/*
 * Module: r2-streamer-kotlin
 * Developers: Mickaël Menu
 *
 * Copyright (c) 2020. Readium Foundation. All rights reserved.
 * Use of this source code is governed by a BSD-style license which is detailed in the
 * LICENSE file present in the project repository where this source code is maintained.
 */

package org.readium.r2.streamer.fetcher.drm

import org.readium.r2.shared.drm.DRM
import org.readium.r2.shared.drm.DRMLicense
import org.readium.r2.shared.extensions.inflate
import org.readium.r2.shared.publication.Link
import org.readium.r2.shared.publication.encryption.encryption
import timber.log.Timber
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.util.*

/** Decrypts DRM encrypted content. **/
internal class DrmDecoder {

    fun decoding(input: InputStream, resourceLink: Link, drm: DRM?): InputStream {
        // Checks if the resource is encrypted and whether the encryption schemes of the resource
        // and the DRM license are the same.
        val license = drm?.license
        val encryption = resourceLink.properties.encryption
        if (license == null || encryption == null || encryption.scheme != drm.scheme.rawValue) {
            return input
        }

        val originalLength = encryption.originalLength?.toInt()
        val isDeflated = (encryption.compression?.toLowerCase(Locale.ROOT) == "deflate")
        val isCBC = (encryption.algorithm == "http://www.w3.org/2001/04/xmlenc#aes256-cbc")

        return if (isDeflated || !isCBC || originalLength == null)
            decryptFully(input, resourceLink, license, isDeflated = isDeflated)
        else
            CbcDrmInputStream(input, resourceLink, license)
    }

    private fun decryptFully(inputStream: InputStream, link: Link, license: DRMLicense, isDeflated: Boolean): InputStream {
        try {
            // Reads the data from the original stream.
            var bytes = inputStream.readBytes()
            inputStream.close()

            // Decrypts it.
            bytes = license.decipher(bytes)
                ?.takeIf { bytes.isNotEmpty() }
                ?: return inputStream

            // Removes the padding.
            val padding = bytes.last().toInt()
            bytes = bytes.copyOfRange(0, bytes.size - padding)

            // If the ressource was compressed using deflate, inflates it.
            if (isDeflated) {
                bytes = bytes.inflate(nowrap = true)
                    ?: return inputStream
            }

            return ByteArrayInputStream(bytes)
        } catch (e: Exception) {
            Timber.e(e, "Failed to decrypt fully the resource: ${link.href}")
            return inputStream
        }
    }

}

