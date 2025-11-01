import java.io.*;
import java.security.SecureRandom;

/**
 * Main.java
 * Command-line application for cryptographic operations using SHA-3 and SHAKE.
 * TCSS 487 Cryptography Project Part 1.
 *
 * Supported commands:
 * - hash256 <inputFile> <outputFile>
 * - hash512 <inputFile> <outputFile>
 * - shake128mac <inputFile> <outputFile> <passphrase> <tagLength>
 * - shake256mac <inputFile> <outputFile> <passphrase> <tagLength>
 * - encrypt <inputFile> <outputFile> <passphrase>
 * - decrypt <inputFile> <outputFile> <passphrase>
 *
 * @author Student
 * @version 1.0
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
        System.out.println("TCSS 487 Cryptography Project - Symmetric Cryptography Library");
        System.out.println("\nUsage:");
        System.out.println("  hash256 <inputFile> <outputFile>");
        System.out.println("  hash512 <inputFile> <outputFile>");
        System.out.println("  hash224 <inputFile> <outputFile>  [BONUS]");
        System.out.println("  hash384 <inputFile> <outputFile>  [BONUS]");
        System.out.println("  shake128mac <inputFile> <outputFile> <passphrase> <tagLength>");
        System.out.println("  shake256mac <inputFile> <outputFile> <passphrase> <tagLength>");
        System.out.println("  encrypt <inputFile> <outputFile> <passphrase>");
        System.out.println("  decrypt <inputFile> <outputFile> <passphrase>");
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
        // Per specification: Use SHA3-256 static method
        byte[] macInput = new byte[key.length + ciphertext.length];
        System.arraycopy(key, 0, macInput, 0, key.length);
        System.arraycopy(ciphertext, 0, macInput, key.length, ciphertext.length);
        byte[] mac = SHA3SHAKE.SHA3(256, macInput, null);

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
        // Per specification: Use SHA3-256 static method
        byte[] macInput = new byte[key.length + ciphertext.length];
        System.arraycopy(key, 0, macInput, 0, key.length);
        System.arraycopy(ciphertext, 0, macInput, key.length, ciphertext.length);
        byte[] computedMAC = SHA3SHAKE.SHA3(256, macInput, null);

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
}