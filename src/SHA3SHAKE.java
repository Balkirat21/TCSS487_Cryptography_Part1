/**
 * SHA3SHAKE.java
 * Implementation of SHA-3 and SHAKE algorithms based on Keccak-f[1600] permutation.
 * FIPS 202 compliant implementation for TCSS 487 Cryptography Project Part 1.
 *
 * Usage Rules:
 * - init() must be called before absorb()
 * - After any squeeze() or digest(), you must call init() again to reuse the object
 * - absorb() and squeeze() cannot be mixed without reset
 * - Each digest() call returns the same hash (unless re-initialized)
 * - Each squeeze() call continues the output stream
 *
 * @author Balkirat Singh
 * @author Jakita Kaur
 * @version 1.0
 */
public class SHA3SHAKE {

    // Keccak state: 5x5 lanes of 64-bit words = 1600 bits
    private long[][] state;

    // Rate (r) and capacity (c) in bytes
    private int rate;
    private int capacity;

    // Current position in the rate portion during absorption
    private int absorbOffset;

    // Current position in the rate portion during squeezing
    private int squeezeOffset;

    // Buffer for absorbing data
    private byte[] buffer;

    // Domain separation suffix
    private byte domainSuffix;

    // Output digest size (for SHA-3 only)
    private int digestSize;

    // Phase tracking
    private boolean initialized;
    private boolean finalized;
    private boolean squeezing;

    // Cached digest result (for repeating digest() calls)
    private byte[] cachedDigest;

    // Keccak round constants
    private static final long[] RC = {
            0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL,
            0x8000000080008000L, 0x000000000000808bL, 0x0000000080000001L,
            0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL,
            0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
            0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L,
            0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
            0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L,
            0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
    };

    // Rotation offsets for rho step (FIPS 202 Table 2)
    // RHO_OFFSETS[x][y] gives the rotation offset for state[x][y]
    private static final int[][] RHO_OFFSETS = {
            {0, 36, 3, 41, 18},
            {1, 44, 10, 45, 2},
            {62, 6, 43, 15, 61},
            {28, 55, 25, 21, 56},
            {27, 20, 39, 8, 14}
    };

    /**
     * Constructor - creates a new SHA3SHAKE instance.
     */
    public SHA3SHAKE() {
        state = new long[5][5];
        buffer = new byte[200]; // Maximum rate for SHA3-224
        initialized = false;
        finalized = false;
        squeezing = false;
    }

    /**
     * Initialize the SHA-3/SHAKE sponge.
     * The suffix must be one of 224, 256, 384, or 512 for SHA-3,
     * or one of 128 or 256 for SHAKE.
     *
     * @param suffix SHA-3/SHAKE suffix (SHA-3 digest bitlength = suffix, SHAKE security level = suffix)
     */
    public void init(int suffix) {
        // Clear state
        for (int i = 0; i < 5; i++) {
            for (int j = 0; j < 5; j++) {
                state[i][j] = 0;
            }
        }

        // Clear buffer
        for (int i = 0; i < buffer.length; i++) {
            buffer[i] = 0;
        }

        // Set capacity and rate based on suffix
        // Note: suffix==256 is ambiguous (could be SHA3-256 or SHAKE256)
        // We check SHA-3 specific values first, then SHAKE-specific, then handle 256
        if (suffix == 224 || suffix == 384 || suffix == 512) {
            // SHA-3 (unambiguous values)
            capacity = 2 * suffix / 8;
            rate = 200 - capacity;
            domainSuffix = 0x06;
            digestSize = suffix / 8;
        } else if (suffix == 128) {
            // SHAKE-128 (unambiguous)
            capacity = 2 * suffix / 8;
            rate = 200 - capacity;
            domainSuffix = 0x1F;
            digestSize = 0;
        } else if (suffix == 256) {
            // Ambiguous: could be SHA3-256 or SHAKE256
            // We defer the decision: if digest() is called -> SHA3-256, if squeeze() -> SHAKE256
            // Set capacity/rate (same for both), but leave domain and size to be determined later
            capacity = 2 * suffix / 8;
            rate = 200 - capacity;
            domainSuffix = (byte) 0xFF; // Sentinel value - will be set during finalization
            digestSize = -1; // Sentinel value - will be determined by which method is called
        } else {
            throw new IllegalArgumentException("Invalid suffix: " + suffix);
        }

        absorbOffset = 0;
        squeezeOffset = 0;
        initialized = true;
        finalized = false;
        squeezing = false;
        cachedDigest = null;
    }

    /**
     * Update the sponge with a byte chunk.
     *
     * @param data input data
     * @param pos starting position in data
     * @param len length of data to absorb
     */
    public void absorb(byte[] data, int pos, int len) {
        if (!initialized) {
            throw new IllegalStateException("Must call init() before absorb()");
        }
        if (finalized || squeezing) {
            throw new IllegalStateException("Cannot absorb after squeezing/digest. Call init() first.");
        }

        int remaining = len;
        int dataOffset = pos;

        while (remaining > 0) {
            int toCopy = Math.min(remaining, rate - absorbOffset);
            System.arraycopy(data, dataOffset, buffer, absorbOffset, toCopy);
            absorbOffset += toCopy;
            dataOffset += toCopy;
            remaining -= toCopy;

            if (absorbOffset == rate) {
                // XOR buffer into state and permute
                xorBufferIntoState();
                keccakF();
                absorbOffset = 0;
                // Clear buffer for next block
                for (int i = 0; i < rate; i++) {
                    buffer[i] = 0;
                }
            }
        }
    }

    /**
     * Update the sponge with a byte chunk.
     *
     * @param data input data
     * @param len length of data to absorb
     */
    public void absorb(byte[] data, int len) {
        absorb(data, 0, len);
    }

    /**
     * Update the sponge with a byte array.
     *
     * @param data input data
     */
    public void absorb(byte[] data) {
        absorb(data, 0, data.length);
    }

    /**
     * Finalize absorption phase with padding and domain suffix.
     * This is called internally before first squeeze/digest.
     */
    private void finalizeAbsorption() {
        if (finalized) {
            return; // Already finalized
        }

        // Apply padding: pad10*1
        // The domain suffix bits are XOR'd at the current position
        buffer[absorbOffset] ^= domainSuffix;

        // Clear any remaining bytes (should already be 0, but be explicit)
        for (int i = absorbOffset + 1; i < rate - 1; i++) {
            buffer[i] = 0;
        }

        // The final padding bit (0x80) is XOR'd at the last byte of the rate
        buffer[rate - 1] ^= (byte) 0x80;

        // Final absorption
        xorBufferIntoState();
        keccakF();

        finalized = true;
        squeezeOffset = 0;
    }

    /**
     * Squeeze hashed bytes from the sponge.
     * Each call continues from where the previous squeeze left off.
     *
     * @param out output buffer
     * @param len number of bytes to squeeze
     * @return output buffer
     */
    public byte[] squeeze(byte[] out, int len) {
        if (!initialized) {
            throw new IllegalStateException("Must call init() before squeeze()");
        }

        // Handle ambiguous init(256) case - resolve to SHAKE256
        if (digestSize == -1) {
            domainSuffix = 0x1F; // SHAKE domain separation
            digestSize = 0; // Variable output for SHAKE
        }

        // Finalize absorption if not already done
        if (!finalized) {
            finalizeAbsorption();
        }

        squeezing = true;

        int remaining = len;
        int outOffset = 0;

        while (remaining > 0) {
            // If we've exhausted current block, permute to get more
            if (squeezeOffset >= rate) {
                keccakF();
                squeezeOffset = 0;
            }

            int toCopy = Math.min(remaining, rate - squeezeOffset);
            extractFromState(out, outOffset, toCopy);
            squeezeOffset += toCopy;
            outOffset += toCopy;
            remaining -= toCopy;
        }

        return out;
    }

    /**
     * Squeeze hashed bytes from the sponge.
     *
     * @param len number of bytes to squeeze
     * @return squeezed bytes
     */
    public byte[] squeeze(int len) {
        return squeeze(new byte[len], len);
    }

    /**
     * Produce a SHA-3 digest.
     * Repeated calls return the same digest without re-initializing.
     *
     * @param out output buffer
     * @return digest bytes
     */
    public byte[] digest(byte[] out) {
        if (!initialized) {
            throw new IllegalStateException("Must call init() before digest()");
        }

        // Handle ambiguous init(256) case - resolve to SHA3-256
        if (digestSize == -1) {
            domainSuffix = 0x06; // SHA-3 domain separation
            digestSize = 32; // 256 bits = 32 bytes
        }

        if (digestSize == 0) {
            throw new IllegalStateException("digest() is only for SHA-3, not SHAKE. Use squeeze() instead.");
        }

        if (out.length < digestSize) {
            throw new IllegalArgumentException("Output buffer too small. Need " + digestSize + " bytes.");
        }

        // Return cached digest if already computed
        if (cachedDigest != null) {
            System.arraycopy(cachedDigest, 0, out, 0, digestSize);
            return out;
        }

        // Finalize and squeeze the digest
        if (!finalized) {
            finalizeAbsorption();
        }

        squeezing = true;

        // Squeeze exactly digestSize bytes
        cachedDigest = new byte[digestSize];
        extractFromState(cachedDigest, 0, digestSize);
        squeezeOffset = digestSize;

        System.arraycopy(cachedDigest, 0, out, 0, digestSize);
        return out;
    }

    /**
     * Produce a SHA-3 digest with auto-sized output.
     *
     * @return digest bytes
     */
    public byte[] digest() {
        // Handle ambiguous init(256) case - resolve to SHA3-256
        if (digestSize == -1) {
            domainSuffix = 0x06; // SHA-3 domain separation
            digestSize = 32; // 256 bits = 32 bytes
        }

        if (digestSize == 0) {
            throw new IllegalStateException("digest() is only for SHA-3, not SHAKE. Use squeeze() instead.");
        }
        return digest(new byte[digestSize]);
    }

    /**
     * Static SHA-3 hash function.
     *
     * @param suffix digest bit length (224, 256, 384, or 512)
     * @param X input data
     * @param out output buffer (if null, this method allocates it with the required size)
     * @return digest bytes
     */
    public static byte[] SHA3(int suffix, byte[] X, byte[] out) {
        if (out == null) {
            out = new byte[suffix / 8];
        }
        SHA3SHAKE s = new SHA3SHAKE();

        // Special handling for SHA3-256 to avoid ambiguity with SHAKE256
        if (suffix == 256) {
            // Manually configure for SHA3-256
            s.state = new long[5][5];
            s.buffer = new byte[200];
            for (int i = 0; i < 5; i++) {
                for (int j = 0; j < 5; j++) {
                    s.state[i][j] = 0;
                }
            }
            for (int i = 0; i < s.buffer.length; i++) {
                s.buffer[i] = 0;
            }
            s.capacity = 2 * 256 / 8;
            s.rate = 200 - s.capacity;
            s.domainSuffix = 0x06; // SHA-3 domain separation (not SHAKE's 0x1F)
            s.digestSize = 256 / 8;
            s.absorbOffset = 0;
            s.squeezeOffset = 0;
            s.initialized = true;
            s.finalized = false;
            s.squeezing = false;
            s.cachedDigest = null;
        } else {
            s.init(suffix);
        }

        s.absorb(X);
        return s.digest(out);
    }

    /**
     * Static SHAKE extendable-output function.
     *
     * @param suffix security level (128 or 256)
     * @param X input data
     * @param L output bit length (must be multiple of 8)
     * @param out output buffer (if null, this method allocates it with the required size)
     * @return output bytes
     */
    public static byte[] SHAKE(int suffix, byte[] X, int L, byte[] out) {
        if (out == null) {
            out = new byte[L / 8];
        }
        SHA3SHAKE s = new SHA3SHAKE();
        s.init(suffix);
        s.absorb(X);
        return s.squeeze(out, L / 8);
    }

    /**
     * XOR buffer into state (little-endian).
     */
    private void xorBufferIntoState() {
        for (int i = 0; i < rate / 8; i++) {
            int x = i % 5;
            int y = i / 5;
            state[x][y] ^= bytesToLong(buffer, i * 8);
        }
    }

    /**
     * Extract bytes from state (little-endian).
     */
    private void extractFromState(byte[] out, int outOffset, int len) {
        int extracted = 0;
        int laneIndex = squeezeOffset / 8; // Which 64-bit lane to start from
        int byteInLane = squeezeOffset % 8; // Byte offset within that lane

        while (extracted < len) {
            int x = laneIndex % 5;
            int y = laneIndex / 5;

            // Extract bytes from current lane
            int bytesFromLane = Math.min(8 - byteInLane, len - extracted);
            for (int i = 0; i < bytesFromLane; i++) {
                out[outOffset + extracted] = (byte) ((state[x][y] >>> ((byteInLane + i) * 8)) & 0xFF);
                extracted++;
            }

            laneIndex++;
            byteInLane = 0;
        }
    }

    /**
     * Keccak-f[1600] permutation (24 rounds).
     */
    private void keccakF() {
        for (int round = 0; round < 24; round++) {
            theta();
            rhoAndPi();
            chi();
            iota(round);
        }
    }

    /**
     * Theta step: XOR each bit with parity of two columns.
     */
    private void theta() {
        long[] C = new long[5];
        long[] D = new long[5];

        // Compute column parity
        for (int x = 0; x < 5; x++) {
            C[x] = state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4];
        }

        // Compute D and XOR into state
        for (int x = 0; x < 5; x++) {
            D[x] = C[(x + 4) % 5] ^ rotateLeft(C[(x + 1) % 5], 1);
            for (int y = 0; y < 5; y++) {
                state[x][y] ^= D[x];
            }
        }
    }

    /**
     * Rho and Pi steps: rotate and permute lanes.
     */
    private void rhoAndPi() {
        long[][] temp = new long[5][5];
        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                int newX = y;
                int newY = (2 * x + 3 * y) % 5;
                temp[newX][newY] = rotateLeft(state[x][y], RHO_OFFSETS[x][y]);
            }
        }
        state = temp;
    }

    /**
     * Chi step: nonlinear mixing.
     */
    private void chi() {
        for (int y = 0; y < 5; y++) {
            long[] row = new long[5];
            for (int x = 0; x < 5; x++) {
                row[x] = state[x][y];
            }
            for (int x = 0; x < 5; x++) {
                state[x][y] = row[x] ^ ((~row[(x + 1) % 5]) & row[(x + 2) % 5]);
            }
        }
    }

    /**
     * Iota step: add round constant.
     */
    private void iota(int round) {
        state[0][0] ^= RC[round];
    }

    /**
     * Rotate long left by n bits.
     */
    private static long rotateLeft(long value, int n) {
        return (value << n) | (value >>> (64 - n));
    }

    /**
     * Convert 8 bytes to long (little-endian).
     */
    private static long bytesToLong(byte[] bytes, int offset) {
        long result = 0;
        for (int i = 0; i < 8; i++) {
            result |= ((long) (bytes[offset + i] & 0xFF)) << (8 * i);
        }
        return result;
    }
}