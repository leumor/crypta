package network.crypta.crypto

import kotlin.experimental.xor

/**
 * Implements the Rijndael cipher with 256-bit block and 256-bit key sizes.
 *
 * This class provides a complete implementation of the Rijndael algorithm, which was the
 * basis for the Advanced Encryption Standard (AES). While the AES standard (FIPS-197)
 * only specifies a block size of 128 bits, the original Rijndael algorithm supports
 * block and key sizes of 128, 192, and 256 bits. This implementation specifically uses
 * a 256-bit block size and a 256-bit key size.
 *
 * The class supports single-block encryption/decryption as well as Cipher Feedback (CFB)
 * mode for handling data of arbitrary length, both as a single operation and in a
 * streaming fashion.
 *
 * @property roundKeys The expanded key schedule derived from the user-provided key.
 * @constructor Creates an instance of the Rijndael256 cipher.
 * @param key The 256-bit (32-byte) secret key to use for all encryption and decryption operations.
 * @throws IllegalArgumentException if the key is not 32 bytes long.
 * @see [FIPS-197](https://csrc.nist.gov/publications/detail/fips/197/final)
 */
class Rijndael256(key: ByteArray) {
    companion object {
        /** The number of 32-bit columns comprising the State (block size / 32). For 256-bit blocks, Nb = 8. */
        private const val Nb = 8

        /** The number of 32-bit words comprising the Cipher Key (key size / 32). For 256-bit keys, Nk = 8. */
        private const val Nk = 8

        /** The number of rounds for a 256-bit key and 256-bit block, which is 14. */
        private const val Nr = 14

        /** The shift offsets for each row in the `ShiftRows` transformation. */
        private val shiftOffsets = intArrayOf(0, 1, 3, 4)

        /**
         * The forward substitution box (S-box).
         * Used in the [subBytes] transformation to provide non-linearity.
         */
        private val S = byteArrayOf(
            99.toByte(),
            124.toByte(),
            119.toByte(),
            123.toByte(),
            242.toByte(),
            107.toByte(),
            111.toByte(),
            197.toByte(),
            48.toByte(),
            1.toByte(),
            103.toByte(),
            43.toByte(),
            254.toByte(),
            215.toByte(),
            171.toByte(),
            118.toByte(),
            202.toByte(),
            130.toByte(),
            201.toByte(),
            125.toByte(),
            250.toByte(),
            89.toByte(),
            71.toByte(),
            240.toByte(),
            173.toByte(),
            212.toByte(),
            162.toByte(),
            175.toByte(),
            156.toByte(),
            164.toByte(),
            114.toByte(),
            192.toByte(),
            183.toByte(),
            253.toByte(),
            147.toByte(),
            38.toByte(),
            54.toByte(),
            63.toByte(),
            247.toByte(),
            204.toByte(),
            52.toByte(),
            165.toByte(),
            229.toByte(),
            241.toByte(),
            113.toByte(),
            216.toByte(),
            49.toByte(),
            21.toByte(),
            4.toByte(),
            199.toByte(),
            35.toByte(),
            195.toByte(),
            24.toByte(),
            150.toByte(),
            5.toByte(),
            154.toByte(),
            7.toByte(),
            18.toByte(),
            128.toByte(),
            226.toByte(),
            235.toByte(),
            39.toByte(),
            178.toByte(),
            117.toByte(),
            9.toByte(),
            131.toByte(),
            44.toByte(),
            26.toByte(),
            27.toByte(),
            110.toByte(),
            90.toByte(),
            160.toByte(),
            82.toByte(),
            59.toByte(),
            214.toByte(),
            179.toByte(),
            41.toByte(),
            227.toByte(),
            47.toByte(),
            132.toByte(),
            83.toByte(),
            209.toByte(),
            0.toByte(),
            237.toByte(),
            32.toByte(),
            252.toByte(),
            177.toByte(),
            91.toByte(),
            106.toByte(),
            203.toByte(),
            190.toByte(),
            57.toByte(),
            74.toByte(),
            76.toByte(),
            88.toByte(),
            207.toByte(),
            208.toByte(),
            239.toByte(),
            170.toByte(),
            251.toByte(),
            67.toByte(),
            77.toByte(),
            51.toByte(),
            133.toByte(),
            69.toByte(),
            249.toByte(),
            2.toByte(),
            127.toByte(),
            80.toByte(),
            60.toByte(),
            159.toByte(),
            168.toByte(),
            81.toByte(),
            163.toByte(),
            64.toByte(),
            143.toByte(),
            146.toByte(),
            157.toByte(),
            56.toByte(),
            245.toByte(),
            188.toByte(),
            182.toByte(),
            218.toByte(),
            33.toByte(),
            16.toByte(),
            255.toByte(),
            243.toByte(),
            210.toByte(),
            205.toByte(),
            12.toByte(),
            19.toByte(),
            236.toByte(),
            95.toByte(),
            151.toByte(),
            68.toByte(),
            23.toByte(),
            196.toByte(),
            167.toByte(),
            126.toByte(),
            61.toByte(),
            100.toByte(),
            93.toByte(),
            25.toByte(),
            115.toByte(),
            96.toByte(),
            129.toByte(),
            79.toByte(),
            220.toByte(),
            34.toByte(),
            42.toByte(),
            144.toByte(),
            136.toByte(),
            70.toByte(),
            238.toByte(),
            184.toByte(),
            20.toByte(),
            222.toByte(),
            94.toByte(),
            11.toByte(),
            219.toByte(),
            224.toByte(),
            50.toByte(),
            58.toByte(),
            10.toByte(),
            73.toByte(),
            6.toByte(),
            36.toByte(),
            92.toByte(),
            194.toByte(),
            211.toByte(),
            172.toByte(),
            98.toByte(),
            145.toByte(),
            149.toByte(),
            228.toByte(),
            121.toByte(),
            231.toByte(),
            200.toByte(),
            55.toByte(),
            109.toByte(),
            141.toByte(),
            213.toByte(),
            78.toByte(),
            169.toByte(),
            108.toByte(),
            86.toByte(),
            244.toByte(),
            234.toByte(),
            101.toByte(),
            122.toByte(),
            174.toByte(),
            8.toByte(),
            186.toByte(),
            120.toByte(),
            37.toByte(),
            46.toByte(),
            28.toByte(),
            166.toByte(),
            180.toByte(),
            198.toByte(),
            232.toByte(),
            221.toByte(),
            116.toByte(),
            31.toByte(),
            75.toByte(),
            189.toByte(),
            139.toByte(),
            138.toByte(),
            112.toByte(),
            62.toByte(),
            181.toByte(),
            102.toByte(),
            72.toByte(),
            3.toByte(),
            246.toByte(),
            14.toByte(),
            97.toByte(),
            53.toByte(),
            87.toByte(),
            185.toByte(),
            134.toByte(),
            193.toByte(),
            29.toByte(),
            158.toByte(),
            225.toByte(),
            248.toByte(),
            152.toByte(),
            17.toByte(),
            105.toByte(),
            217.toByte(),
            142.toByte(),
            148.toByte(),
            155.toByte(),
            30.toByte(),
            135.toByte(),
            233.toByte(),
            206.toByte(),
            85.toByte(),
            40.toByte(),
            223.toByte(),
            140.toByte(),
            161.toByte(),
            137.toByte(),
            13.toByte(),
            191.toByte(),
            230.toByte(),
            66.toByte(),
            104.toByte(),
            65.toByte(),
            153.toByte(),
            45.toByte(),
            15.toByte(),
            176.toByte(),
            84.toByte(),
            187.toByte(),
            22.toByte()
        )

        /**
         * The inverse substitution box (S-box).
         * Used in the [invSubBytes] transformation to reverse the substitution.
         */
        private val Si = byteArrayOf(
            82.toByte(),
            9.toByte(),
            106.toByte(),
            213.toByte(),
            48.toByte(),
            54.toByte(),
            165.toByte(),
            56.toByte(),
            191.toByte(),
            64.toByte(),
            163.toByte(),
            158.toByte(),
            129.toByte(),
            243.toByte(),
            215.toByte(),
            251.toByte(),
            124.toByte(),
            227.toByte(),
            57.toByte(),
            130.toByte(),
            155.toByte(),
            47.toByte(),
            255.toByte(),
            135.toByte(),
            52.toByte(),
            142.toByte(),
            67.toByte(),
            68.toByte(),
            196.toByte(),
            222.toByte(),
            233.toByte(),
            203.toByte(),
            84.toByte(),
            123.toByte(),
            148.toByte(),
            50.toByte(),
            166.toByte(),
            194.toByte(),
            35.toByte(),
            61.toByte(),
            238.toByte(),
            76.toByte(),
            149.toByte(),
            11.toByte(),
            66.toByte(),
            250.toByte(),
            195.toByte(),
            78.toByte(),
            8.toByte(),
            46.toByte(),
            161.toByte(),
            102.toByte(),
            40.toByte(),
            217.toByte(),
            36.toByte(),
            178.toByte(),
            118.toByte(),
            91.toByte(),
            162.toByte(),
            73.toByte(),
            109.toByte(),
            139.toByte(),
            209.toByte(),
            37.toByte(),
            114.toByte(),
            248.toByte(),
            246.toByte(),
            100.toByte(),
            134.toByte(),
            104.toByte(),
            152.toByte(),
            22.toByte(),
            212.toByte(),
            164.toByte(),
            92.toByte(),
            204.toByte(),
            93.toByte(),
            101.toByte(),
            182.toByte(),
            146.toByte(),
            108.toByte(),
            112.toByte(),
            72.toByte(),
            80.toByte(),
            253.toByte(),
            237.toByte(),
            185.toByte(),
            218.toByte(),
            94.toByte(),
            21.toByte(),
            70.toByte(),
            87.toByte(),
            167.toByte(),
            141.toByte(),
            157.toByte(),
            132.toByte(),
            144.toByte(),
            216.toByte(),
            171.toByte(),
            0.toByte(),
            140.toByte(),
            188.toByte(),
            211.toByte(),
            10.toByte(),
            247.toByte(),
            228.toByte(),
            88.toByte(),
            5.toByte(),
            184.toByte(),
            179.toByte(),
            69.toByte(),
            6.toByte(),
            208.toByte(),
            44.toByte(),
            30.toByte(),
            143.toByte(),
            202.toByte(),
            63.toByte(),
            15.toByte(),
            2.toByte(),
            193.toByte(),
            175.toByte(),
            189.toByte(),
            3.toByte(),
            1.toByte(),
            19.toByte(),
            138.toByte(),
            107.toByte(),
            58.toByte(),
            145.toByte(),
            17.toByte(),
            65.toByte(),
            79.toByte(),
            103.toByte(),
            220.toByte(),
            234.toByte(),
            151.toByte(),
            242.toByte(),
            207.toByte(),
            206.toByte(),
            240.toByte(),
            180.toByte(),
            230.toByte(),
            115.toByte(),
            150.toByte(),
            172.toByte(),
            116.toByte(),
            34.toByte(),
            231.toByte(),
            173.toByte(),
            53.toByte(),
            133.toByte(),
            226.toByte(),
            249.toByte(),
            55.toByte(),
            232.toByte(),
            28.toByte(),
            117.toByte(),
            223.toByte(),
            110.toByte(),
            71.toByte(),
            241.toByte(),
            26.toByte(),
            113.toByte(),
            29.toByte(),
            41.toByte(),
            197.toByte(),
            137.toByte(),
            111.toByte(),
            183.toByte(),
            98.toByte(),
            14.toByte(),
            170.toByte(),
            24.toByte(),
            190.toByte(),
            27.toByte(),
            252.toByte(),
            86.toByte(),
            62.toByte(),
            75.toByte(),
            198.toByte(),
            210.toByte(),
            121.toByte(),
            32.toByte(),
            154.toByte(),
            219.toByte(),
            192.toByte(),
            254.toByte(),
            120.toByte(),
            205.toByte(),
            90.toByte(),
            244.toByte(),
            31.toByte(),
            221.toByte(),
            168.toByte(),
            51.toByte(),
            136.toByte(),
            7.toByte(),
            199.toByte(),
            49.toByte(),
            177.toByte(),
            18.toByte(),
            16.toByte(),
            89.toByte(),
            39.toByte(),
            128.toByte(),
            236.toByte(),
            95.toByte(),
            96.toByte(),
            81.toByte(),
            127.toByte(),
            169.toByte(),
            25.toByte(),
            181.toByte(),
            74.toByte(),
            13.toByte(),
            45.toByte(),
            229.toByte(),
            122.toByte(),
            159.toByte(),
            147.toByte(),
            201.toByte(),
            156.toByte(),
            239.toByte(),
            160.toByte(),
            224.toByte(),
            59.toByte(),
            77.toByte(),
            174.toByte(),
            42.toByte(),
            245.toByte(),
            176.toByte(),
            200.toByte(),
            235.toByte(),
            187.toByte(),
            60.toByte(),
            131.toByte(),
            83.toByte(),
            153.toByte(),
            97.toByte(),
            23.toByte(),
            43.toByte(),
            4.toByte(),
            126.toByte(),
            186.toByte(),
            119.toByte(),
            214.toByte(),
            38.toByte(),
            225.toByte(),
            105.toByte(),
            20.toByte(),
            99.toByte(),
            85.toByte(),
            33.toByte(),
            12.toByte(),
            125.toByte()
        )

        /**
         * The round constants (Rcon).
         * Used in the key expansion schedule to introduce round-dependent transformations.
         */
        private val rcon = intArrayOf(
            0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a
        )
    }

    private val roundKeys: IntArray = keyExpansion(key)

    /** The feedback register for streaming Cipher Feedback (CFB) mode. It holds the last ciphertext block. */
    private val feedback = ByteArray(32)

    /** A pointer into the feedback register, indicating the next byte to be used for the keystream. */
    private var registerPointer = 0

    /**
     * Encrypts a single 256-bit (32-byte) block of data.
     *
     * This method applies the core Rijndael algorithm transformations to the input block.
     * Note: This is a raw block encryption, equivalent to ECB mode for a single block.
     * For multiple blocks, consider using a mode of operation like CFB (see [encryptCfb]).
     *
     * @param block The 32-byte plaintext block to encrypt.
     * @return The 32-byte encrypted ciphertext block.
     * @throws IllegalArgumentException if the block is not 32 bytes long.
     */
    fun encrypt(block: ByteArray): ByteArray {
        require(block.size == 32) { "Block must be 256 bits" }
        val state = Array(4) { ByteArray(Nb) }
        for (i in block.indices) {
            state[i % 4][i / 4] = block[i]
        }
        addRoundKey(state, 0)
        for (round in 1 until Nr) {
            subBytes(state)
            shiftRows(state)
            mixColumns(state)
            addRoundKey(state, round)
        }
        subBytes(state)
        shiftRows(state)
        addRoundKey(state, Nr)
        val out = ByteArray(32)
        for (c in 0 until Nb) {
            for (r in 0 until 4) {
                out[4 * c + r] = state[r][c]
            }
        }
        return out
    }

    /**
     * Decrypts a single 256-bit (32-byte) block of data.
     *
     * This method applies the inverse Rijndael algorithm transformations to the input block.
     * Note: This is a raw block decryption. For multiple blocks, use a proper mode of
     * operation like CFB (see [decryptCfb]).
     *
     * @param block The 32-byte ciphertext block to decrypt.
     * @return The 32-byte decrypted plaintext block.
     * @throws IllegalArgumentException if the block is not 32 bytes long.
     */
    fun decrypt(block: ByteArray): ByteArray {
        require(block.size == 32) { "Block must be 256 bits" }
        val state = Array(4) { ByteArray(Nb) }
        for (i in block.indices) {
            state[i % 4][i / 4] = block[i]
        }
        addRoundKey(state, Nr)
        for (round in Nr - 1 downTo 1) {
            invShiftRows(state)
            invSubBytes(state)
            addRoundKey(state, round)
            invMixColumns(state)
        }
        invShiftRows(state)
        invSubBytes(state)
        addRoundKey(state, 0)
        val out = ByteArray(32)
        for (c in 0 until Nb) {
            for (r in 0 until 4) {
                out[4 * c + r] = state[r][c]
            }
        }
        return out
    }

    /**
     * Encrypts arbitrary-length data using Cipher Feedback (CFB) mode with no padding.
     *
     * This method is suitable for encrypting data that is not a multiple of the block size.
     * It creates a new feedback chain for each call and is not intended for streaming.
     *
     * @param data The plaintext data to encrypt.
     * @param iv The initialization vector, which must be exactly 32 bytes (256 bits).
     * @return The encrypted ciphertext.
     * @throws IllegalArgumentException if the IV is not 32 bytes long.
     */
    fun encryptCfb(data: ByteArray, iv: ByteArray): ByteArray {
        require(iv.size == 32) { "IV must be 256 bits" }
        var feedback = iv.copyOf()
        val out = ByteArray(data.size)
        var offset = 0
        while (offset < data.size) {
            val keystream = encrypt(feedback)
            val blockLen = minOf(32, data.size - offset)
            for (i in 0 until blockLen) {
                out[offset + i] = (keystream[i] xor data[offset + i])
            }
            feedback = if (blockLen == 32) {
                out.copyOfRange(offset, offset + 32)
            } else {
                val newFeedback = ByteArray(32)
                for (i in 0 until 32 - blockLen) newFeedback[i] = feedback[i + blockLen]
                for (i in 0 until blockLen) newFeedback[32 - blockLen + i] = out[offset + i]
                newFeedback
            }
            offset += blockLen
        }
        return out
    }

    /**
     * Decrypts data that was encrypted with [encryptCfb] using Cipher Feedback (CFB) mode.
     *
     * The decryption process for CFB mode is nearly identical to encryption.
     * The same initialization vector (IV) used for encryption must be provided.
     *
     * @param data The ciphertext data to decrypt.
     * @param iv The initialization vector, which must be exactly 32 bytes (256 bits).
     * @return The decrypted plaintext.
     * @throws IllegalArgumentException if the IV is not 32 bytes long.
     */
    fun decryptCfb(data: ByteArray, iv: ByteArray): ByteArray {
        require(iv.size == 32) { "IV must be 256 bits" }
        var feedback = iv.copyOf()
        val out = ByteArray(data.size)
        var offset = 0
        while (offset < data.size) {
            val keystream = encrypt(feedback)
            val blockLen = minOf(32, data.size - offset)
            for (i in 0 until blockLen) {
                out[offset + i] = (keystream[i] xor data[offset + i])
            }
            feedback = if (blockLen == 32) {
                data.copyOfRange(offset, offset + 32)
            } else {
                val newFeedback = ByteArray(32)
                for (i in 0 until 32 - blockLen) newFeedback[i] = feedback[i + blockLen]
                for (i in 0 until blockLen) newFeedback[32 - blockLen + i] = data[offset + i]
                newFeedback
            }
            offset += blockLen
        }
        return out
    }

    /**
     * Initializes or resets the internal state for streaming Cipher Feedback (CFB) mode.
     *
     * This must be called before starting a new encryption or decryption stream.
     *
     * @param iv The initialization vector, which must be 32 bytes (256 bits).
     * @throws IllegalArgumentException if the IV is not 32 bytes long.
     */
    fun resetCfb(iv: ByteArray) {
        require(iv.size == 32) { "IV must be 256 bits" }
        iv.copyInto(feedback)
        registerPointer = feedback.size
    }

    /**
     * Encrypts a portion of data using the internal streaming CFB state.
     *
     * [resetCfb] must be called first to initialize the stream. This method can then be
     * called multiple times to encrypt a stream of data in chunks.
     *
     * @param data The byte array containing the data to encrypt.
     * @param offset The starting offset in the `data` array.
     * @param length The number of bytes to encrypt.
     * @return A new byte array containing the encrypted data.
     */
    fun encryptCfb(data: ByteArray, offset: Int, length: Int): ByteArray {
        val out = data.copyOfRange(offset, offset + length)
        blockEncipher(out, 0, length)
        return out
    }

    /**
     * Decrypts a portion of data using the internal streaming CFB state.
     *
     * [resetCfb] must be called first with the same IV used for encryption. This method can
     * then be called multiple times to decrypt a stream of data in chunks.
     *
     * @param data The byte array containing the data to decrypt.
     * @param offset The starting offset in the `data` array.
     * @param length The number of bytes to decrypt.
     * @return A new byte array containing the decrypted data.
     */
    fun decryptCfb(data: ByteArray, offset: Int, length: Int): ByteArray {
        val out = data.copyOfRange(offset, offset + length)
        blockDecipher(out, 0, length)
        return out
    }

    /** Core logic for streaming CFB encryption, processing byte by byte and refilling the buffer as needed. */
    private fun blockEncipher(buf: ByteArray, offIn: Int, lenIn: Int) {
        var off = offIn
        var len = lenIn
        val fbLen = feedback.size
        if (registerPointer != 0) {
            var l = minOf(fbLen - registerPointer, len)
            len -= l
            while (l-- > 0) {
                val b = (feedback[registerPointer] xor buf[off])
                feedback[registerPointer] = b
                buf[off] = b
                registerPointer++
                off++
            }
            if (len == 0) return
            refillBuffer()
        }
        while (len > fbLen) {
            len -= fbLen
            while (registerPointer < fbLen) {
                val b = (feedback[registerPointer] xor buf[off])
                feedback[registerPointer] = b
                buf[off] = b
                registerPointer++
                off++
            }
            refillBuffer()
        }
        while (len-- > 0) {
            val b = (feedback[registerPointer] xor buf[off])
            feedback[registerPointer] = b
            buf[off] = b
            registerPointer++
            off++
        }
    }

    /** Core logic for streaming CFB decryption, processing byte by byte and refilling the buffer as needed. */
    private fun blockDecipher(buf: ByteArray, offIn: Int, lenIn: Int) {
        var off = offIn
        var len = lenIn
        val fbLen = feedback.size
        if (registerPointer != 0) {
            var l = minOf(fbLen - registerPointer, len)
            len -= l
            while (l-- > 0) {
                val b = buf[off]
                buf[off] = (b xor feedback[registerPointer])
                feedback[registerPointer] = b
                registerPointer++
                off++
            }
            if (len == 0) return
            refillBuffer()
        }
        while (len > fbLen) {
            len -= fbLen
            while (registerPointer < fbLen) {
                val b = buf[off]
                buf[off] = (b xor feedback[registerPointer])
                feedback[registerPointer] = b
                registerPointer++
                off++
            }
            refillBuffer()
        }
        while (len-- > 0) {
            val b = buf[off]
            buf[off] = (b xor feedback[registerPointer])
            feedback[registerPointer] = b
            registerPointer++
            off++
        }
    }

    /** Refills the feedback buffer by encrypting its current content. */
    private fun refillBuffer() {
        val enc = encrypt(feedback)
        enc.copyInto(feedback)
        registerPointer = 0
    }

    /** XORs the state with a portion of the round key for the given round. */
    private fun addRoundKey(state: Array<ByteArray>, round: Int) {
        for (c in 0 until Nb) {
            val word = roundKeys[round * Nb + c]
            state[0][c] = (state[0][c].toInt() xor (word ushr 24)).toByte()
            state[1][c] = (state[1][c].toInt() xor (word ushr 16)).toByte()
            state[2][c] = (state[2][c].toInt() xor (word ushr 8)).toByte()
            state[3][c] = (state[3][c].toInt() xor word).toByte()
        }
    }

    /** Applies the forward S-box substitution to each byte of the state. */
    private fun subBytes(s: Array<ByteArray>) {
        for (r in 0 until 4) for (c in 0 until Nb) {
            val v = s[r][c].toInt() and 0xff
            s[r][c] = S[v]
        }
    }

    /** Applies the inverse S-box substitution to each byte of the state. */
    private fun invSubBytes(s: Array<ByteArray>) {
        for (r in 0 until 4) for (c in 0 until Nb) {
            val v = s[r][c].toInt() and 0xff
            s[r][c] = Si[v]
        }
    }

    /** Cyclically shifts the rows of the state by different offsets. */
    private fun shiftRows(s: Array<ByteArray>) {
        for (r in 1 until 4) {
            val row = ByteArray(Nb)
            val shift = shiftOffsets[r]
            for (c in 0 until Nb) row[c] = s[r][(c + shift) % Nb]
            s[r].indices.forEach { c -> s[r][c] = row[c] }
        }
    }

    /** Cyclically shifts the rows of the state back to their original positions. */
    private fun invShiftRows(s: Array<ByteArray>) {
        for (r in 1 until 4) {
            val row = ByteArray(Nb)
            val shift = shiftOffsets[r]
            for (c in 0 until Nb) row[c] = s[r][(c - shift + Nb) % Nb]
            s[r].indices.forEach { c -> s[r][c] = row[c] }
        }
    }

    /** Mixes the data within each column of the state to provide diffusion. */
    private fun mixColumns(s: Array<ByteArray>) {
        for (c in 0 until Nb) {
            val a0 = s[0][c].toInt() and 0xff
            val a1 = s[1][c].toInt() and 0xff
            val a2 = s[2][c].toInt() and 0xff
            val a3 = s[3][c].toInt() and 0xff
            s[0][c] = (mul(a0, 2) xor mul(a1, 3) xor a2 xor a3).toByte()
            s[1][c] = (a0 xor mul(a1, 2) xor mul(a2, 3) xor a3).toByte()
            s[2][c] = (a0 xor a1 xor mul(a2, 2) xor mul(a3, 3)).toByte()
            s[3][c] = (mul(a0, 3) xor a1 xor a2 xor mul(a3, 2)).toByte()
        }
    }

    /** Reverses the mixing of data within each column of the state. */
    private fun invMixColumns(s: Array<ByteArray>) {
        for (c in 0 until Nb) {
            val a0 = s[0][c].toInt() and 0xff
            val a1 = s[1][c].toInt() and 0xff
            val a2 = s[2][c].toInt() and 0xff
            val a3 = s[3][c].toInt() and 0xff
            s[0][c] = (mul(a0, 0x0e) xor mul(a1, 0x0b) xor mul(a2, 0x0d) xor mul(a3, 0x09)).toByte()
            s[1][c] = (mul(a0, 0x09) xor mul(a1, 0x0e) xor mul(a2, 0x0b) xor mul(a3, 0x0d)).toByte()
            s[2][c] = (mul(a0, 0x0d) xor mul(a1, 0x09) xor mul(a2, 0x0e) xor mul(a3, 0x0b)).toByte()
            s[3][c] = (mul(a0, 0x0b) xor mul(a1, 0x0d) xor mul(a2, 0x09) xor mul(a3, 0x0e)).toByte()
        }
    }

    /**
     * Generates the key schedule from the initial 256-bit cipher key.
     * @param key The 32-byte secret key.
     * @return An array of integers representing the expanded round keys.
     */
    private fun keyExpansion(key: ByteArray): IntArray {
        require(key.size == 32) { "Key must be 256 bits" }
        val w = IntArray(Nb * (Nr + 1))
        var i = 0
        var pos = 0
        while (i < Nk) {
            w[i] = (key[pos].toInt() and 0xff shl 24) or
                    (key[pos + 1].toInt() and 0xff shl 16) or
                    (key[pos + 2].toInt() and 0xff shl 8) or
                    (key[pos + 3].toInt() and 0xff)
            pos += 4
            i++
        }
        i = Nk
        var rconIdx = 0
        while (i < Nb * (Nr + 1)) {
            var temp = w[i - 1]
            if (i % Nk == 0) {
                temp = subWord(rotWord(temp)) xor (rcon[rconIdx++] shl 24)
            } else if (Nk > 6 && i % Nk == 4) {
                temp = subWord(temp)
            }
            w[i] = w[i - Nk] xor temp
            i++
        }
        return w
    }

    /** Applies the S-box to a 32-bit word, byte by byte. Used in key expansion. */
    private fun subWord(word: Int): Int {
        return (S[(word ushr 24) and 0xff].toInt() and 0xff shl 24) or
                (S[(word ushr 16) and 0xff].toInt() and 0xff shl 16) or
                (S[(word ushr 8) and 0xff].toInt() and 0xff shl 8) or
                (S[word and 0xff].toInt() and 0xff)
    }

    /** Rotates the bytes of a 32-bit word to the left. Used in key expansion. */
    private fun rotWord(word: Int): Int = (word shl 8) or (word ushr 24)

    /** Performs multiplication in the Galois Field GF(2^8). */
    private fun mul(a: Int, b: Int): Int {
        var aa = a
        var bb = b
        var res = 0
        while (bb != 0) {
            if (bb and 1 != 0) res = res xor aa
            aa = xtime(aa)
            bb = bb shr 1
        }
        return res and 0xff
    }

    /** Helper function for Galois Field multiplication, equivalent to multiplying by x (or {02}). */
    private fun xtime(a: Int): Int {
        val res = a shl 1
        return if (a and 0x80 != 0) (res xor 0x1b) and 0xff else res and 0xff
    }
}

/**
 * An implementation of [CryptoCipher] using a custom [Rijndael256] engine in PCFB mode.
 *
 * PCFB (Propagating Cipher Feedback) is a stream cipher mode of operation. This class
 * wraps a [Rijndael256] engine to provide the [CryptoCipher] interface.
 *
 * Note: The underlying [Rijndael256] engine is stateful for streaming operations.
 * One-shot methods are safe, but a single [Rijndael256Cipher] instance should not be
 * used for multiple concurrent streaming operations. New streams should be created via
 * [encryptor] and [decryptor] for each concurrent task.
 *
 * @property key The raw key bytes for the Rijndael-256 algorithm.
 * @constructor Creates a `Rijndael256Cipher` with the given key.
 */
internal class Rijndael256Cipher(key: ByteArray) : CryptoCipher {
    /**
     * The underlying stateful [Rijndael256] engine instance.
     * This engine holds the key and the state for CFB mode operations.
     */
    private val engine = Rijndael256(key)

    /**
     * Encrypts data using the stateful engine's PCFB mode in a single operation.
     * The engine's internal state is initialized with the [iv] for this operation.
     */
    override fun encrypt(iv: ByteArray, data: ByteArray): ByteArray =
        engine.encryptCfb(data, iv)

    /**
     * Decrypts data using the stateful engine's PCFB mode in a single operation.
     * The engine's internal state is initialized with the [iv] for this operation.
     */
    override fun decrypt(iv: ByteArray, data: ByteArray): ByteArray =
        engine.decryptCfb(data, iv)

    /**
     * Creates a new stateful stream for encrypting data in chunks using PCFB mode.
     *
     * This method first resets the internal state of the [engine] with the provided [iv],
     * then returns a [CryptoCipherStream] that will process subsequent data chunks.
     *
     * @param iv The initialization vector for the CFB stream.
     * @return A new [CryptoCipherStream] for encryption.
     */
    override fun encryptor(iv: ByteArray): CryptoCipherStream {
        engine.resetCfb(iv)
        return object : CryptoCipherStream {
            override fun update(data: ByteArray, offset: Int, length: Int): ByteArray =
                engine.encryptCfb(data, offset, length)
        }
    }

    /**
     * Creates a new stateful stream for decrypting data in chunks using PCFB mode.
     *
     * This method first resets the internal state of the [engine] with the provided [iv],
     * then returns a [CryptoCipherStream] that will process subsequent data chunks.
     *
     * @param iv The initialization vector for the CFB stream.
     * @return A new [CryptoCipherStream] for decryption.
     */
    override fun decryptor(iv: ByteArray): CryptoCipherStream {
        engine.resetCfb(iv)
        return object : CryptoCipherStream {
            override fun update(data: ByteArray, offset: Int, length: Int): ByteArray =
                engine.decryptCfb(data, offset, length)
        }
    }
}