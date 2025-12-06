import java.io.*;
import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Main.java
 * Command-line application for cryptographic operations using SHA-3, SHAKE, and Elliptic Curves.
 * TCSS 487 Cryptography Project Part 1 & Part 2.
 *
 * Part 1 - Symmetric Cryptography:
 * - hash256 <inputFile> <outputFile>
 * - hash512 <inputFile> <outputFile>
 * - shake128mac <inputFile> <outputFile> <passphrase> <tagLength>
 * - shake256mac <inputFile> <outputFile> <passphrase> <tagLength>
 * - encrypt <inputFile> <outputFile> <passphrase>
 * - decrypt <inputFile> <outputFile> <passphrase>
 *
 * Part 2 - Elliptic Curve Cryptography:
 * - genkey <passphrase> <publicKeyFile>
 * - ecencrypt <inputFile> <outputFile> <publicKeyFile>
 * - ecdecrypt <inputFile> <outputFile> <passphrase>
 * - sign <inputFile> <signatureFile> <passphrase>
 * - verify <inputFile> <signatureFile> <publicKeyFile>
 * - signenc <inputFile> <outputFile> <senderPassphrase> <recipientPublicKey>
 * - decverify <inputFile> <outputFile> <recipientPassphrase> <senderPublicKey>
 *
 * @author Balkirat Singh
 * @author Jakita Kaur
 * @version 2.0
 */
public class Main {

    /**
     * Main entry point.
     *
     * @param args command-line arguments
     */
    public static void main(String[] args) {
        if (args.length < 3) {
            printUsage();
            return;
        }

        String command = args[0].toLowerCase();

        try {
            switch (command) {
                case "hash256":
                    if (args.length != 3) {
                        System.err.println("Usage: hash256 <inputFile> <outputFile>");
                        return;
                    }
                    hashFile(args[1], args[2], 256);
                    break;

                case "hash512":
                    if (args.length != 3) {
                        System.err.println("Usage: hash512 <inputFile> <outputFile>");
                        return;
                    }
                    hashFile(args[1], args[2], 512);
                    break;

                case "hash224":
                    if (args.length != 3) {
                        System.err.println("Usage: hash224 <inputFile> <outputFile>");
                        return;
                    }
                    hashFile(args[1], args[2], 224);
                    break;

                case "hash384":
                    if (args.length != 3) {
                        System.err.println("Usage: hash384 <inputFile> <outputFile>");
                        return;
                    }
                    hashFile(args[1], args[2], 384);
                    break;

                case "shake128mac":
                    if (args.length != 5) {
                        System.err.println("Usage: shake128mac <inputFile> <outputFile> <passphrase> <tagLength>");
                        return;
                    }
                    generateMAC(args[1], args[2], args[3], Integer.parseInt(args[4]), 128);
                    break;

                case "shake256mac":
                    if (args.length != 5) {
                        System.err.println("Usage: shake256mac <inputFile> <outputFile> <passphrase> <tagLength>");
                        return;
                    }
                    generateMAC(args[1], args[2], args[3], Integer.parseInt(args[4]), 256);
                    break;

                case "encrypt":
                    if (args.length != 4) {
                        System.err.println("Usage: encrypt <inputFile> <outputFile> <passphrase>");
                        return;
                    }
                    encryptFile(args[1], args[2], args[3]);
                    break;

                case "decrypt":
                    if (args.length != 4) {
                        System.err.println("Usage: decrypt <inputFile> <outputFile> <passphrase>");
                        return;
                    }
                    decryptFile(args[1], args[2], args[3]);
                    break;

                case "genkey":
                    if (args.length != 3) {
                        System.err.println("Usage: genkey <passphrase> <publicKeyFile>");
                        return;
                    }
                    generateKeyPair(args[1], args[2]);
                    break;

                case "ecencrypt":
                    if (args.length != 4) {
                        System.err.println("Usage: ecencrypt <inputFile> <outputFile> <publicKeyFile>");
                        return;
                    }
                    eciesEncrypt(args[1], args[2], args[3]);
                    break;

                case "ecdecrypt":
                    if (args.length != 4) {
                        System.err.println("Usage: ecdecrypt <inputFile> <outputFile> <passphrase>");
                        return;
                    }
                    eciesDecrypt(args[1], args[2], args[3]);
                    break;

                case "sign":
                    if (args.length != 4) {
                        System.err.println("Usage: sign <inputFile> <signatureFile> <passphrase>");
                        return;
                    }
                    schnorrSign(args[1], args[2], args[3]);
                    break;

                case "verify":
                    if (args.length != 4) {
                        System.err.println("Usage: verify <inputFile> <signatureFile> <publicKeyFile>");
                        return;
                    }
                    schnorrVerify(args[1], args[2], args[3]);
                    break;

                case "signenc":
                    if (args.length != 5) {
                        System.err.println("Usage: signenc <inputFile> <outputFile> <senderPassphrase> <recipientPublicKey>");
                        return;
                    }
                    signThenEncrypt(args[1], args[2], args[3], args[4]);
                    break;

                case "decverify":
                    if (args.length != 5) {
                        System.err.println("Usage: decverify <inputFile> <outputFile> <recipientPassphrase> <senderPublicKey>");
                        return;
                    }
                    decryptThenVerify(args[1], args[2], args[3], args[4]);
                    break;

                default:
                    System.err.println("Unknown command: " + command);
                    printUsage();
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Print usage information.
     */
    private static void printUsage() {
        System.out.println("TCSS 487 Cryptography Project - Symmetric & Elliptic Curve Cryptography Library");
        System.out.println("\nPart 1 - Symmetric Cryptography:");
        System.out.println("  hash256 <inputFile> <outputFile>");
        System.out.println("  hash512 <inputFile> <outputFile>");
        System.out.println("  hash224 <inputFile> <outputFile>  [BONUS]");
        System.out.println("  hash384 <inputFile> <outputFile>  [BONUS]");
        System.out.println("  shake128mac <inputFile> <outputFile> <passphrase> <tagLength>");
        System.out.println("  shake256mac <inputFile> <outputFile> <passphrase> <tagLength>");
        System.out.println("  encrypt <inputFile> <outputFile> <passphrase>");
        System.out.println("  decrypt <inputFile> <outputFile> <passphrase>");
        System.out.println("\nPart 2 - Elliptic Curve Cryptography:");
        System.out.println("  genkey <passphrase> <publicKeyFile>");
        System.out.println("  ecencrypt <inputFile> <outputFile> <publicKeyFile>");
        System.out.println("  ecdecrypt <inputFile> <outputFile> <passphrase>");
        System.out.println("  sign <inputFile> <signatureFile> <passphrase>");
        System.out.println("  verify <inputFile> <signatureFile> <publicKeyFile>");
        System.out.println("  signenc <inputFile> <outputFile> <senderPassphrase> <recipientPublicKey>  [BONUS]");
        System.out.println("  decverify <inputFile> <outputFile> <recipientPassphrase> <senderPublicKey>  [BONUS]");
    }

    /**
     * Hash a file using SHA-3.
     *
     * @param inputFile input file path
     * @param outputFile output file path
     * @param suffix hash bit length (224, 256, 384, or 512)
     * @throws IOException if file operations fail
     */
    private static void hashFile(String inputFile, String outputFile, int suffix) throws IOException {
        System.out.println("Computing SHA3-" + suffix + " hash of " + inputFile + "...");

        byte[] input = readFile(inputFile);
        byte[] hash = SHA3SHAKE.SHA3(suffix, input, null); // Let method allocate

        writeFile(outputFile, hash);

        System.out.println("Hash written to " + outputFile);
        System.out.println("Hash (hex): " + bytesToHex(hash));
    }

    /**
     * Generate a SHAKE-based MAC.
     *
     * @param inputFile input file path
     * @param outputFile output file path
     * @param passphrase authentication key
     * @param tagLength MAC length in bytes
     * @param suffix SHAKE variant (128 or 256)
     * @throws IOException if file operations fail
     */
    private static void generateMAC(String inputFile, String outputFile, String passphrase,
                                    int tagLength, int suffix) throws IOException {
        System.out.println("Generating SHAKE-" + suffix + " MAC (" + tagLength + " bytes) for " + inputFile + "...");

        byte[] input = readFile(inputFile);
        byte[] passphraseBytes = passphrase.getBytes("UTF-8");

        // Per specification: absorb(passphrase), absorb(data), absorb("T"), then squeeze
        SHA3SHAKE shake = new SHA3SHAKE();
        shake.init(suffix);
        shake.absorb(passphraseBytes);
        shake.absorb(input);
        shake.absorb("T".getBytes("UTF-8")); // Final tag "T"
        byte[] mac = shake.squeeze(tagLength);

        writeFile(outputFile, mac);

        System.out.println("MAC written to " + outputFile);
        System.out.println("MAC (hex): " + bytesToHex(mac));
    }

    /**
     * Encrypt a file using SHAKE-128 keystream.
     *
     * @param inputFile input plaintext file
     * @param outputFile output cryptogram file
     * @param passphrase encryption passphrase
     * @throws IOException if file operations fail
     */
    private static void encryptFile(String inputFile, String outputFile, String passphrase) throws IOException {
        System.out.println("Encrypting " + inputFile + "...");

        byte[] plaintext = readFile(inputFile);
        byte[] passphraseBytes = passphrase.getBytes("UTF-8");

        // 1. Derive key from passphrase: key = SHAKE-128(passphrase, 128 bits)
        byte[] key = SHA3SHAKE.SHAKE(128, passphraseBytes, 128, null); // Let method allocate

        // 2. Generate random 128-bit nonce
        SecureRandom random = new SecureRandom();
        byte[] nonce = new byte[16]; // 128 bits = 16 bytes
        random.nextBytes(nonce);

        // 3. Generate keystream: SHAKE-128(nonce || key)
        // Per specification: init SHAKE-128, absorb(nonce), absorb(key), squeeze
        SHA3SHAKE shake = new SHA3SHAKE();
        shake.init(128);
        shake.absorb(nonce);
        shake.absorb(key);
        byte[] keystream = shake.squeeze(plaintext.length);

        // 4. XOR plaintext with keystream
        byte[] ciphertext = xor(plaintext, keystream);

        // 5. Compute MAC over ciphertext (BONUS)
        // Per specification: init SHA3-256, absorb(key), absorb(ciphertext), digest()
        SHA3SHAKE sha3 = new SHA3SHAKE();
        sha3.init(256);
        sha3.absorb(key);
        sha3.absorb(ciphertext);
        byte[] mac = sha3.digest();

        // 6. Create cryptogram: nonce || ciphertext || MAC
        byte[] cryptogram = new byte[nonce.length + ciphertext.length + mac.length];
        System.arraycopy(nonce, 0, cryptogram, 0, nonce.length);
        System.arraycopy(ciphertext, 0, cryptogram, nonce.length, ciphertext.length);
        System.arraycopy(mac, 0, cryptogram, nonce.length + ciphertext.length, mac.length);

        writeFile(outputFile, cryptogram);

        System.out.println("Encryption complete. Output written to " + outputFile);
        System.out.println("Cryptogram size: " + cryptogram.length + " bytes");
        System.out.println("Nonce (hex): " + bytesToHex(nonce));
    }

    /**
     * Decrypt a file using SHAKE-128 keystream.
     *
     * @param inputFile input cryptogram file
     * @param outputFile output plaintext file
     * @param passphrase decryption passphrase
     * @throws IOException if file operations fail
     */
    private static void decryptFile(String inputFile, String outputFile, String passphrase) throws IOException {
        System.out.println("Decrypting " + inputFile + "...");

        byte[] cryptogram = readFile(inputFile);
        byte[] passphraseBytes = passphrase.getBytes("UTF-8");

        // Check minimum cryptogram size (nonce + MAC)
        if (cryptogram.length < 48) { // 16 + 32
            throw new IOException("Invalid cryptogram: too short");
        }

        // 1. Extract nonce (first 16 bytes)
        byte[] nonce = new byte[16];
        System.arraycopy(cryptogram, 0, nonce, 0, 16);

        // 2. Extract MAC (last 32 bytes)
        byte[] receivedMAC = new byte[32];
        System.arraycopy(cryptogram, cryptogram.length - 32, receivedMAC, 0, 32);

        // 3. Extract ciphertext (middle portion)
        int ciphertextLength = cryptogram.length - 48;
        byte[] ciphertext = new byte[ciphertextLength];
        System.arraycopy(cryptogram, 16, ciphertext, 0, ciphertextLength);

        // 4. Derive key from passphrase
        byte[] key = SHA3SHAKE.SHAKE(128, passphraseBytes, 128, null); // Let method allocate

        // 5. Verify MAC (BONUS)
        // Per specification: init SHA3-256, absorb(key), absorb(ciphertext), digest()
        SHA3SHAKE sha3 = new SHA3SHAKE();
        sha3.init(256);
        sha3.absorb(key);
        sha3.absorb(ciphertext);
        byte[] computedMAC = sha3.digest();

        if (!constantTimeEquals(receivedMAC, computedMAC)) {
            throw new IOException("MAC verification failed: incorrect passphrase or corrupted cryptogram");
        }

        System.out.println("MAC verification successful.");

        // 6. Generate keystream
        // Per specification: init SHAKE-128, absorb(nonce), absorb(key), squeeze
        SHA3SHAKE shake = new SHA3SHAKE();
        shake.init(128);
        shake.absorb(nonce);
        shake.absorb(key);
        byte[] keystream = shake.squeeze(ciphertext.length);

        // 7. XOR ciphertext with keystream to recover plaintext
        byte[] plaintext = xor(ciphertext, keystream);

        writeFile(outputFile, plaintext);

        System.out.println("Decryption complete. Output written to " + outputFile);
        System.out.println("Recovered plaintext size: " + plaintext.length + " bytes");
    }

    /**
     * XOR two byte arrays.
     *
     * @param a first array
     * @param b second array
     * @return XOR result
     */
    private static byte[] xor(byte[] a, byte[] b) {
        if (a.length != b.length) {
            throw new IllegalArgumentException("Arrays must have equal length");
        }
        byte[] result = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }

    /**
     * Constant-time equality check to prevent timing attacks.
     *
     * @param a first array
     * @param b second array
     * @return true if arrays are equal
     */
    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }

    /**
     * Read entire file into byte array.
     *
     * @param filename file path
     * @return file contents
     * @throws IOException if read fails
     */
    private static byte[] readFile(String filename) throws IOException {
        File file = new File(filename);
        byte[] data = new byte[(int) file.length()];

        try (FileInputStream fis = new FileInputStream(file)) {
            int bytesRead = fis.read(data);
            if (bytesRead != data.length) {
                throw new IOException("Could not read entire file");
            }
        }

        return data;
    }

    /**
     * Write byte array to file.
     *
     * @param filename file path
     * @param data data to write
     * @throws IOException if write fails
     */
    private static void writeFile(String filename, byte[] data) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(filename)) {
            fos.write(data);
        }
    }

    /**
     * Convert byte array to hex string.
     *
     * @param bytes input bytes
     * @return hex string
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // ========== Part 2: Elliptic Curve Cryptography Methods ==========

    /**
     * Generate elliptic curve key pair from a passphrase.
     * Outputs the public key V to a file.
     *
     * @param passphrase user passphrase
     * @param publicKeyFile output file for public key
     * @throws Exception if key generation fails
     */
    private static void generateKeyPair(String passphrase, String publicKeyFile) throws Exception {
        System.out.println("Generating key pair from passphrase...");

        Edwards curve = new Edwards();
        Edwards.Point G = curve.gen();

        // Derive private key s from passphrase using SHAKE-128
        byte[] passphraseBytes = passphrase.getBytes("UTF-8");
        byte[] keyMaterial = SHA3SHAKE.SHAKE(128, passphraseBytes, 384, null); // 384 bits = 48 bytes

        // Convert to BigInteger and reduce mod r
        BigInteger s = new BigInteger(1, keyMaterial).mod(curve.getR());

        // Compute public key V = s*G
        Edwards.Point V = G.mul(s);

        // If LSB(V.x) == 1, adjust: s = r - s, V = -V
        if (V.getX().testBit(0)) {
            s = curve.getR().subtract(s);
            V = V.negate();
        }

        // Verify LSB(V.x) == 0
        if (V.getX().testBit(0)) {
            throw new RuntimeException("Failed to normalize public key");
        }

        // Write public key to file: y-coordinate (32 bytes) || x_lsb (1 byte)
        byte[] publicKey = encodePublicKey(V);
        writeFile(publicKeyFile, publicKey);

        System.out.println("Key pair generated successfully.");
        System.out.println("Public key written to " + publicKeyFile);
        System.out.println("Public key (hex): " + bytesToHex(publicKey));
    }

    /**
     * Encrypt a file using ECIES under a given public key.
     *
     * @param inputFile input plaintext file
     * @param outputFile output cryptogram file
     * @param publicKeyFile public key file
     * @throws Exception if encryption fails
     */
    private static void eciesEncrypt(String inputFile, String outputFile, String publicKeyFile) throws Exception {
        System.out.println("Encrypting " + inputFile + " with ECIES...");

        // Read message
        byte[] message = readFile(inputFile);

        // Read public key V
        Edwards curve = new Edwards();
        Edwards.Point V = readPublicKey(publicKeyFile, curve);

        Edwards.Point G = curve.gen();

        // Generate random k mod r
        int rbytes = (curve.getR().bitLength() + 7) >> 3;
        BigInteger k = new BigInteger(
            new SecureRandom().generateSeed(rbytes << 1)
        ).mod(curve.getR());

        // Compute W = k*V
        Edwards.Point W = V.mul(k);

        // Compute Z = k*G
        Edwards.Point Z = G.mul(k);

        // Derive keys from W.y using SHAKE-256
        SHA3SHAKE shake = new SHA3SHAKE();
        shake.init(256);
        shake.absorb(bigIntegerToBytes(W.getY(), 32));
        byte[] ka = shake.squeeze(32); // authentication key
        byte[] ke = shake.squeeze(32); // encryption key

        // Encrypt: c = m XOR SHAKE-128(ke)
        SHA3SHAKE encShake = new SHA3SHAKE();
        encShake.init(128);
        encShake.absorb(ke);
        byte[] keystream = encShake.squeeze(message.length);
        byte[] c = xor(message, keystream);

        // Compute MAC: t = SHA3-256(ka || c)
        SHA3SHAKE sha3 = new SHA3SHAKE();
        sha3.init(256);
        sha3.absorb(ka);
        sha3.absorb(c);
        byte[] t = sha3.digest();

        // Cryptogram: Z || c || t
        byte[] Z_encoded = encodePublicKey(Z);
        byte[] cryptogram = new byte[Z_encoded.length + c.length + t.length];
        System.arraycopy(Z_encoded, 0, cryptogram, 0, Z_encoded.length);
        System.arraycopy(c, 0, cryptogram, Z_encoded.length, c.length);
        System.arraycopy(t, 0, cryptogram, Z_encoded.length + c.length, t.length);

        writeFile(outputFile, cryptogram);

        System.out.println("Encryption complete. Output written to " + outputFile);
        System.out.println("Cryptogram size: " + cryptogram.length + " bytes");
    }

    /**
     * Decrypt an ECIES cryptogram using a password-derived private key.
     *
     * @param inputFile input cryptogram file
     * @param outputFile output plaintext file
     * @param passphrase decryption passphrase
     * @throws Exception if decryption fails
     */
    private static void eciesDecrypt(String inputFile, String outputFile, String passphrase) throws Exception {
        System.out.println("Decrypting " + inputFile + " with ECIES...");

        // Read cryptogram
        byte[] cryptogram = readFile(inputFile);

        // Parse cryptogram: Z (33 bytes) || c || t (32 bytes)
        if (cryptogram.length < 65) {
            throw new IOException("Invalid cryptogram: too short");
        }

        byte[] Z_encoded = new byte[33];
        System.arraycopy(cryptogram, 0, Z_encoded, 0, 33);

        byte[] t = new byte[32];
        System.arraycopy(cryptogram, cryptogram.length - 32, t, 0, 32);

        int cLen = cryptogram.length - 65;
        byte[] c = new byte[cLen];
        System.arraycopy(cryptogram, 33, c, 0, cLen);

        // Recover Z from encoded form
        Edwards curve = new Edwards();
        Edwards.Point Z = decodePublicKey(Z_encoded, curve);

        // Derive private key s from passphrase
        byte[] passphraseBytes = passphrase.getBytes("UTF-8");
        byte[] keyMaterial = SHA3SHAKE.SHAKE(128, passphraseBytes, 384, null);
        BigInteger s = new BigInteger(1, keyMaterial).mod(curve.getR());

        Edwards.Point G = curve.gen();
        Edwards.Point V = G.mul(s);

        // Adjust s if needed (LSB normalization)
        if (V.getX().testBit(0)) {
            s = curve.getR().subtract(s);
        }

        // Compute W = s*Z
        Edwards.Point W = Z.mul(s);

        // Derive keys from W.y using SHAKE-256
        SHA3SHAKE shake = new SHA3SHAKE();
        shake.init(256);
        shake.absorb(bigIntegerToBytes(W.getY(), 32));
        byte[] ka = shake.squeeze(32); // authentication key
        byte[] ke = shake.squeeze(32); // encryption key

        // Verify MAC: t' = SHA3-256(ka || c)
        SHA3SHAKE sha3 = new SHA3SHAKE();
        sha3.init(256);
        sha3.absorb(ka);
        sha3.absorb(c);
        byte[] t_prime = sha3.digest();

        if (!constantTimeEquals(t, t_prime)) {
            throw new IOException("MAC verification failed: incorrect passphrase or corrupted cryptogram");
        }

        System.out.println("MAC verification successful.");

        // Decrypt: m = c XOR SHAKE-128(ke)
        SHA3SHAKE decShake = new SHA3SHAKE();
        decShake.init(128);
        decShake.absorb(ke);
        byte[] keystream = decShake.squeeze(c.length);
        byte[] message = xor(c, keystream);

        writeFile(outputFile, message);

        System.out.println("Decryption complete. Output written to " + outputFile);
        System.out.println("Recovered plaintext size: " + message.length + " bytes");
    }

    /**
     * Sign a file using Schnorr signatures.
     *
     * @param inputFile input file to sign
     * @param signatureFile output signature file
     * @param passphrase signer's passphrase
     * @throws Exception if signing fails
     */
    private static void schnorrSign(String inputFile, String signatureFile, String passphrase) throws Exception {
        System.out.println("Signing " + inputFile + " with Schnorr signature...");

        // Read message
        byte[] message = readFile(inputFile);

        Edwards curve = new Edwards();
        Edwards.Point G = curve.gen();

        // Derive private key s from passphrase
        byte[] passphraseBytes = passphrase.getBytes("UTF-8");
        byte[] keyMaterial = SHA3SHAKE.SHAKE(128, passphraseBytes, 384, null);
        BigInteger s = new BigInteger(1, keyMaterial).mod(curve.getR());

        Edwards.Point V = G.mul(s);
        if (V.getX().testBit(0)) {
            s = curve.getR().subtract(s);
        }

        // Generate random k mod r (enhanced method)
        int rbytes = (curve.getR().bitLength() + 7) >> 3;
        byte[] seed = new SecureRandom().generateSeed(rbytes << 1);

        SHA3SHAKE kShake = new SHA3SHAKE();
        kShake.init(256);
        kShake.absorb(bigIntegerToBytes(s, rbytes));
        kShake.absorb(message);
        kShake.absorb(seed);
        byte[] kBytes = kShake.squeeze(rbytes << 1);
        BigInteger k = new BigInteger(1, kBytes).mod(curve.getR());

        // Compute U = k*G
        Edwards.Point U = G.mul(k);

        // Compute h = SHA3-256(U.y || m) mod r
        SHA3SHAKE sha3 = new SHA3SHAKE();
        sha3.init(256);
        sha3.absorb(bigIntegerToBytes(U.getY(), 32));
        sha3.absorb(message);
        byte[] hashBytes = sha3.digest();
        BigInteger h = new BigInteger(1, hashBytes).mod(curve.getR());

        // Compute z = (k - h*s) mod r
        BigInteger z = k.subtract(h.multiply(s)).mod(curve.getR());

        // Write signature: h (32 bytes) || z (32 bytes)
        byte[] signature = new byte[64];
        byte[] hBytes = bigIntegerToBytes(h, 32);
        byte[] zBytes = bigIntegerToBytes(z, 32);
        System.arraycopy(hBytes, 0, signature, 0, 32);
        System.arraycopy(zBytes, 0, signature, 32, 32);

        writeFile(signatureFile, signature);

        System.out.println("Signature generated successfully.");
        System.out.println("Signature written to " + signatureFile);
    }

    /**
     * Verify a Schnorr signature.
     *
     * @param inputFile input file that was signed
     * @param signatureFile signature file
     * @param publicKeyFile signer's public key file
     * @throws Exception if verification fails
     */
    private static void schnorrVerify(String inputFile, String signatureFile, String publicKeyFile) throws Exception {
        System.out.println("Verifying Schnorr signature for " + inputFile + "...");

        // Read message
        byte[] message = readFile(inputFile);

        // Read signature: h (32 bytes) || z (32 bytes)
        byte[] signature = readFile(signatureFile);
        if (signature.length != 64) {
            throw new IOException("Invalid signature length");
        }

        byte[] hBytes = new byte[32];
        byte[] zBytes = new byte[32];
        System.arraycopy(signature, 0, hBytes, 0, 32);
        System.arraycopy(signature, 32, zBytes, 0, 32);

        BigInteger h = new BigInteger(1, hBytes);
        BigInteger z = new BigInteger(1, zBytes);

        // Read public key V
        Edwards curve = new Edwards();
        Edwards.Point V = readPublicKey(publicKeyFile, curve);
        Edwards.Point G = curve.gen();

        // Compute U' = z*G + h*V
        Edwards.Point U_prime = G.mul(z).add(V.mul(h));

        // Compute h' = SHA3-256(U'.y || m) mod r
        SHA3SHAKE sha3 = new SHA3SHAKE();
        sha3.init(256);
        sha3.absorb(bigIntegerToBytes(U_prime.getY(), 32));
        sha3.absorb(message);
        byte[] hashBytes = sha3.digest();
        BigInteger h_prime = new BigInteger(1, hashBytes).mod(curve.getR());

        // Verify h' == h
        if (h.equals(h_prime)) {
            System.out.println("Signature verification: ACCEPTED");
            System.out.println("The signature is valid.");
        } else {
            System.out.println("Signature verification: REJECTED");
            System.out.println("The signature is invalid.");
            System.exit(1); // Exit with error code for failed verification
        }
    }

    /**
     * Sign a file with Schnorr, then encrypt with ECIES (bonus).
     *
     * @param inputFile input file
     * @param outputFile output cryptogram file
     * @param senderPassphrase sender's passphrase (for signing)
     * @param recipientPublicKeyFile recipient's public key file (for encryption)
     * @throws Exception if operation fails
     */
    private static void signThenEncrypt(String inputFile, String outputFile,
                                       String senderPassphrase, String recipientPublicKeyFile) throws Exception {
        System.out.println("Sign-then-encrypt operation on " + inputFile + "...");

        // Step 1: Sign the file
        String tempSigFile = outputFile + ".temp.sig";
        schnorrSign(inputFile, tempSigFile, senderPassphrase);

        // Step 2: Read message and signature
        byte[] message = readFile(inputFile);
        byte[] signature = readFile(tempSigFile);

        // Step 3: Create combined payload: message || signature
        byte[] payload = new byte[message.length + signature.length];
        System.arraycopy(message, 0, payload, 0, message.length);
        System.arraycopy(signature, 0, payload, message.length, signature.length);

        // Step 4: Write payload to temp file
        String tempPayloadFile = outputFile + ".temp.payload";
        writeFile(tempPayloadFile, payload);

        // Step 5: Encrypt the payload with ECIES
        eciesEncrypt(tempPayloadFile, outputFile, recipientPublicKeyFile);

        // Step 6: Clean up temp files
        new File(tempSigFile).delete();
        new File(tempPayloadFile).delete();

        System.out.println("Sign-then-encrypt complete. Output written to " + outputFile);
    }

    /**
     * Decrypt with ECIES, then verify Schnorr signature (bonus).
     *
     * @param inputFile input cryptogram file
     * @param outputFile output plaintext file
     * @param recipientPassphrase recipient's passphrase (for decryption)
     * @param senderPublicKeyFile sender's public key file (for verification)
     * @throws Exception if operation fails
     */
    private static void decryptThenVerify(String inputFile, String outputFile,
                                         String recipientPassphrase, String senderPublicKeyFile) throws Exception {
        System.out.println("Decrypt-then-verify operation on " + inputFile + "...");

        // Step 1: Decrypt the cryptogram
        String tempPayloadFile = outputFile + ".temp.payload";
        eciesDecrypt(inputFile, tempPayloadFile, recipientPassphrase);

        // Step 2: Read decrypted payload
        byte[] payload = readFile(tempPayloadFile);

        // Step 3: Split payload: message || signature (64 bytes)
        if (payload.length < 64) {
            throw new IOException("Invalid payload: too short for signature");
        }

        int messageLen = payload.length - 64;
        byte[] message = new byte[messageLen];
        byte[] signature = new byte[64];
        System.arraycopy(payload, 0, message, 0, messageLen);
        System.arraycopy(payload, messageLen, signature, 0, 64);

        // Step 4: Write message and signature to temp files
        String tempMessageFile = outputFile + ".temp.msg";
        String tempSigFile = outputFile + ".temp.sig";
        writeFile(tempMessageFile, message);
        writeFile(tempSigFile, signature);

        // Step 5: Verify the signature
        schnorrVerify(tempMessageFile, tempSigFile, senderPublicKeyFile);

        // Step 6: Write recovered message to output file
        writeFile(outputFile, message);

        // Step 7: Clean up temp files
        new File(tempPayloadFile).delete();
        new File(tempMessageFile).delete();
        new File(tempSigFile).delete();

        System.out.println("Decrypt-then-verify complete. Output written to " + outputFile);
    }

    // ========== Helper Methods for Elliptic Curve Operations ==========

    /**
     * Encode a point as: y (32 bytes) || x_lsb (1 byte).
     *
     * @param P point to encode
     * @return encoded point (33 bytes)
     */
    private static byte[] encodePublicKey(Edwards.Point P) {
        byte[] y = bigIntegerToBytes(P.getY(), 32);
        byte x_lsb = (byte) (P.getX().testBit(0) ? 0x01 : 0x00);

        byte[] encoded = new byte[33];
        System.arraycopy(y, 0, encoded, 0, 32);
        encoded[32] = x_lsb;

        return encoded;
    }

    /**
     * Decode a point from: y (32 bytes) || x_lsb (1 byte).
     *
     * @param encoded encoded point (33 bytes)
     * @param curve Edwards curve
     * @return decoded point
     * @throws IOException if decoding fails
     */
    private static Edwards.Point decodePublicKey(byte[] encoded, Edwards curve) throws IOException {
        if (encoded.length != 33) {
            throw new IOException("Invalid public key length");
        }

        byte[] yBytes = new byte[32];
        System.arraycopy(encoded, 0, yBytes, 0, 32);
        BigInteger y = new BigInteger(1, yBytes);

        boolean x_lsb = (encoded[32] == 0x01);

        Edwards.Point P = curve.getPoint(y, x_lsb);

        if (P.isZero()) {
            throw new IOException("Invalid public key: point not on curve or wrong order");
        }

        return P;
    }

    /**
     * Read public key from file.
     *
     * @param filename public key file
     * @param curve Edwards curve
     * @return public key point
     * @throws IOException if read fails
     */
    private static Edwards.Point readPublicKey(String filename, Edwards curve) throws IOException {
        byte[] encoded = readFile(filename);
        return decodePublicKey(encoded, curve);
    }

    /**
     * Convert BigInteger to byte array with fixed size (big-endian, unsigned).
     *
     * @param value BigInteger value
     * @param size desired byte array size
     * @return byte array of specified size
     */
    private static byte[] bigIntegerToBytes(BigInteger value, int size) {
        byte[] bytes = value.toByteArray();

        // Handle sign byte
        if (bytes.length == size + 1 && bytes[0] == 0) {
            byte[] result = new byte[size];
            System.arraycopy(bytes, 1, result, 0, size);
            return result;
        }

        // Pad with zeros if needed
        if (bytes.length < size) {
            byte[] result = new byte[size];
            int offset = size - bytes.length;
            System.arraycopy(bytes, 0, result, offset, bytes.length);
            return result;
        }

        // Truncate if needed (shouldn't happen in normal usage)
        if (bytes.length > size) {
            byte[] result = new byte[size];
            System.arraycopy(bytes, bytes.length - size, result, 0, size);
            return result;
        }

        return bytes;
    }
}