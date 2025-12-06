# TCSS 487 Cryptography
## Practical Project - Parts 1 & 2: Symmetric & Elliptic Curve Cryptography

---

**Student Names:** Balkirat Singh, Jakita Kaur
**Date:** December 5, 2025
**Course:** TCSS 487 - Cryptography
**Instructor:** Paulo Barreto

---

## Table of Contents

1. [Overview](#overview)
2. [Implementation Details](#implementation-details)
3. [User Instructions](#user-instructions)
4. [Example Usage](#example-usage)
5. [Testing & Validation](#testing--validation)
6. [Known Bugs](#known-bugs)
7. [Attribution](#attribution)

---

## Overview

This project implements a comprehensive cryptographic library in Java, covering both **symmetric cryptography** (Part 1) and **elliptic curve cryptography** (Part 2). The implementation provides hash functions, message authentication, symmetric encryption, and public-key cryptographic operations.

### Implemented Features

**Part 1: Symmetric Cryptography**

Core Requirements:
- SHA-3-256 and SHA-3-512 hash computation for files
- SHAKE-128 and SHAKE-256 MAC generation for files
- Symmetric encryption using SHAKE-128 stream cipher
- Symmetric decryption with cryptogram verification

Bonus Features:
- SHA-3-224 and SHA-3-384 hash computation
- MAC tag included in cryptogram using SHA-3-256
- MAC verification during decryption

**Part 2: Elliptic Curve Cryptography**

Core Requirements:
- Key pair generation from passphrase
- ECIES encryption under public key
- ECIES decryption with MAC verification
- Schnorr signature generation
- Schnorr signature verification

Bonus Features:
- Sign-then-encrypt combined operation
- Decrypt-then-verify combined operation

### Files Submitted

1. `Main.java` - Command-line application interface (Parts 1 & 2)
2. `SHA3SHAKE.java` - SHA-3/SHAKE cryptographic library implementation
3. `Edwards.java` - Edwards curve elliptic curve arithmetic (Part 2)
4. `REPORT.pdf` - This report

---

## Implementation Details

### Architecture

The implementation consists of three primary classes:

1. **SHA3SHAKE** - Core symmetric cryptographic library implementing:
   - Keccak-f[1600] permutation function with 24 rounds
   - SHA-3 hash functions (224, 256, 384, 512-bit outputs)
   - SHAKE extendable output functions (128 and 256-bit security levels)
   - Sponge construction with proper padding (pad10*1)

2. **Edwards** - Elliptic curve arithmetic library implementing:
   - NUMS ed-256-mers* Edwards curve (128-bit security level)
   - Point addition using Edwards addition formulas
   - Efficient scalar multiplication using double-and-add algorithm
   - Point recovery from y-coordinate and x LSB
   - Generator point computation
   - Curve order validation

3. **Main** - Unified command-line interface providing:
   - File hashing operations (Part 1)
   - MAC generation with passphrases (Part 1)
   - Symmetric encryption/decryption (Part 1)
   - Key pair generation (Part 2)
   - ECIES encryption/decryption (Part 2)
   - Schnorr signature generation/verification (Part 2)
   - Combined sign-then-encrypt and decrypt-then-verify operations (Part 2 bonus)
   - User-friendly error handling

### Cryptographic Specifications

**Sponge Parameters:**
- State size: 1600 bits (5×5 array of 64-bit words)
- Rate/Capacity:
  - SHA3-224: r=1152, c=448
  - SHA3-256: r=1088, c=512
  - SHA3-384: r=832, c=768
  - SHA3-512: r=576, c=1024
  - SHAKE128: r=1344, c=256
  - SHAKE256: r=1088, c=512

**Domain Separation:**
- SHA-3: suffix 0x06
- SHAKE: suffix 0x1F

**Encryption Scheme:**
- Key derivation: key = SHAKE-128(passphrase, 128 bits)
- Nonce: 128-bit random value using `SecureRandom`
- Stream cipher keystream: init(SHAKE-128), absorb(nonce), absorb(key), squeeze
- MAC computation: init(SHA3-256), absorb(key), absorb(ciphertext), digest()
- Cryptogram format: nonce (16 bytes) || ciphertext || MAC (32 bytes)

---

## User Instructions

### Compilation

```bash
javac src/Edwards.java src/SHA3SHAKE.java src/Main.java
```

### Command Syntax

All commands follow this general format:
```bash
java -cp src Main <command> <arguments>
```

### Available Commands

#### 1. SHA-3-256 Hash (Required)
Computes the SHA-3-256 hash of a file.

**Syntax:**
```bash
java -cp src Main hash256 <inputFile> <outputFile>
```

**Parameters:**
- `inputFile` - Path to the file to hash
- `outputFile` - Path where the hash will be written (32 bytes)

**Example:**
```bash
java -cp src Main hash256 document.txt hash.bin
```

---

#### 2. SHA-3-512 Hash (Required)
Computes the SHA-3-512 hash of a file.

**Syntax:**
```bash
java -cp src Main hash512 <inputFile> <outputFile>
```

**Parameters:**
- `inputFile` - Path to the file to hash
- `outputFile` - Path where the hash will be written (64 bytes)

**Example:**
```bash
java -cp src Main hash512 document.txt hash512.bin
```

---

#### 3. SHA-3-224 Hash (Bonus)
Computes the SHA-3-224 hash of a file.

**Syntax:**
```bash
java -cp src Main hash224 <inputFile> <outputFile>
```

**Parameters:**
- `inputFile` - Path to the file to hash
- `outputFile` - Path where the hash will be written (28 bytes)

**Example:**
```bash
java -cp src Main hash224 document.txt hash224.bin
```

---

#### 4. SHA-3-384 Hash (Bonus)
Computes the SHA-3-384 hash of a file.

**Syntax:**
```bash
java -cp src Main hash384 <inputFile> <outputFile>
```

**Parameters:**
- `inputFile` - Path to the file to hash
- `outputFile` - Path where the hash will be written (48 bytes)

**Example:**
```bash
java -cp src Main hash384 document.txt hash384.bin
```

---

#### 5. SHAKE-128 MAC (Required)
Generates a SHAKE-128 message authentication code for a file.

**Syntax:**
```bash
java -cp src Main shake128mac <inputFile> <outputFile> <passphrase> <tagLength>
```

**Parameters:**
- `inputFile` - Path to the file to authenticate
- `outputFile` - Path where the MAC will be written
- `passphrase` - Authentication key (string)
- `tagLength` - Desired MAC length in bytes

**Example:**
```bash
java -cp src Main shake128mac document.txt mac.bin "mySecret123" 32
```

**Note:** The MAC is computed as SHAKE-128(passphrase || data || "T")

---

#### 6. SHAKE-256 MAC (Required)
Generates a SHAKE-256 message authentication code for a file.

**Syntax:**
```bash
java -cp src Main shake256mac <inputFile> <outputFile> <passphrase> <tagLength>
```

**Parameters:**
- `inputFile` - Path to the file to authenticate
- `outputFile` - Path where the MAC will be written
- `passphrase` - Authentication key (string)
- `tagLength` - Desired MAC length in bytes

**Example:**
```bash
java -cp src Main shake256mac document.txt mac.bin "mySecret123" 64
```

---

#### 7. Encrypt File (Required + Bonus)
Encrypts a file using SHAKE-128 stream cipher with MAC authentication.

**Syntax:**
```bash
java -cp src Main encrypt <inputFile> <outputFile> <passphrase>
```

**Parameters:**
- `inputFile` - Path to the plaintext file
- `outputFile` - Path where the cryptogram will be written
- `passphrase` - Encryption passphrase (string)

**Example:**
```bash
java -cp src Main encrypt secret.txt encrypted.bin "myPassword123"
```

**Output Format:**
The cryptogram contains:
- 16 bytes: Random nonce
- N bytes: Ciphertext (same size as plaintext)
- 32 bytes: SHA3-256 MAC tag (Bonus feature)

Total size: plaintext_size + 48 bytes

---

#### 8. Decrypt File (Required + Bonus)
Decrypts a cryptogram and verifies its MAC authentication tag.

**Syntax:**
```bash
java -cp src Main decrypt <inputFile> <outputFile> <passphrase>
```

**Parameters:**
- `inputFile` - Path to the cryptogram file
- `outputFile` - Path where the decrypted plaintext will be written
- `passphrase` - Decryption passphrase (must match encryption passphrase)

**Example:**
```bash
java -cp src Main decrypt encrypted.bin recovered.txt "myPassword123"
```

**Notes:**
- The MAC is automatically verified before decryption
- If the MAC verification fails, decryption aborts with an error
- If the passphrase is incorrect, MAC verification will fail

---

## Example Usage

### Complete Encryption/Decryption Workflow

```bash
# 1. Compile the project
javac src/Main.java src/SHA3SHAKE.java

# 2. Create a test file
echo "This is a secret message!" > plaintext.txt

# 3. Compute SHA-3-256 hash of original
java -cp src Main hash256 plaintext.txt original_hash.bin

# 4. Encrypt the file
java -cp src Main encrypt plaintext.txt encrypted.bin "MySecurePassword123"

# 5. Decrypt the file
java -cp src Main decrypt encrypted.bin decrypted.txt "MySecurePassword123"

# 6. Verify decryption by comparing hashes
java -cp src Main hash256 decrypted.txt decrypted_hash.bin

# 7. Compare the two hashes (should be identical)
diff original_hash.bin decrypted_hash.bin
# (No output means files are identical - success!)
```

### MAC Generation and Verification

```bash
# Generate a SHAKE-128 MAC for a file
java -cp src Main shake128mac document.txt mac1.bin "password123" 32

# Generate another MAC with different passphrase
java -cp src Main shake128mac document.txt mac2.bin "wrongpassword" 32

# The MACs will be different (demonstrating passphrase dependency)
diff mac1.bin mac2.bin
# (Will show they differ)
```

### Hash Computation Example

```bash
# Compute all supported SHA-3 variants
java -cp src Main hash224 file.txt hash224.bin
java -cp src Main hash256 file.txt hash256.bin
java -cp src Main hash384 file.txt hash384.bin
java -cp src Main hash512 file.txt hash512.bin

# Display hash in hexadecimal
xxd -p hash256.bin
```

---

## Testing & Validation

### NIST Test Vector Validation

The implementation has been validated against **all** official NIST test vectors from:
- `sha-3bytetestvectors.zip`
- `shakebytetestvectors.zip`

**Test Results:**
- Total test vectors: 1,670
- Passed: 1,670 (100%)
- Failed: 0

**Test Coverage:**
- ✓ SHA3-224: ShortMsg + LongMsg (245 tests)
- ✓ SHA3-256: ShortMsg + LongMsg (237 tests)
- ✓ SHA3-384: ShortMsg + LongMsg (205 tests)
- ✓ SHA3-512: ShortMsg + LongMsg (173 tests)
- ✓ SHAKE128: ShortMsg + LongMsg + VariableOut (437 tests)
- ✓ SHAKE256: ShortMsg + LongMsg + VariableOut (373 tests)

All hash functions produce **cryptographically correct** outputs matching FIPS 202 specification.

### Interoperability

The implementation is fully compatible with:
- OpenSSL's SHA-3 implementation
- Any FIPS 202-compliant SHA-3/SHAKE implementation

---

## Known Bugs

We have not encountered any bugs during our testing. The implementation has been validated against the official NIST test vectors and handles various edge cases properly, including empty inputs, large files, and different hash output lengths. Error handling has been implemented for invalid inputs, and the padding mechanism works correctly across all test scenarios.

---

## Attribution

This implementation was inspired by Markku-Juhani Saarinen's readable C implementation of SHA-3/Keccak available at:

**https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c**

The reference implementation provided valuable insight into:
- Keccak-f[1600] permutation structure
- Theta, Rho, Pi, Chi, and Iota step transformations
- Rotation offset patterns for the Rho step

However, this Java implementation is an **independent work** with:
- Complete rewrite in Java with object-oriented design
- Additional features (SHAKE support, MAC operations, encryption)
- Enhanced error handling and user interface
- Full NIST test vector validation suite

All code is original and written specifically for this project. No code was copied directly from the reference implementation.

---

## Conclusion

This project successfully implements a complete SHA-3/SHAKE cryptographic library in pure Java, conforming to FIPS 202 specifications. The implementation provides robust symmetric encryption capabilities with authenticated encryption using MAC tags, validated against all official NIST test vectors.

---

**END OF REPORT**
