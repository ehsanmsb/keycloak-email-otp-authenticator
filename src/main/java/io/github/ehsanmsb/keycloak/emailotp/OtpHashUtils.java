package io.github.ehsanmsb.keycloak.emailotp;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Utility class for OTP hashing operations.
 * <p>
 * OTP codes are never persisted in plaintext. Before being stored in the
 * authentication session, each code is hashed using {@value #HASH_ALGORITHM}.
 * Validation is performed by hashing the submitted code and comparing the
 * resulting digest against the stored hash.
 * </p>
 */
final class OtpHashUtils {

    /**
     * The hashing algorithm used to protect OTP codes at rest.
     * SHA-256 algorithm is mandated by the Java SE specification and is always available.
     */
    static final String HASH_ALGORITHM = "SHA-256";

    private OtpHashUtils() {
        throw new UnsupportedOperationException("OtpHashUtils is a utility class and cannot be instantiated");
    }

    /**
     * Returns the {@value #HASH_ALGORITHM} hex digest of the given OTP code.
     * <p>
     * The raw code is never persisted; only the digest is stored in the
     * authentication session. At validation time, use {@link #matches} to verify
     * a submitted code against the stored digest.
     * </p>
     *
     * @param code the raw OTP code (must not be {@code null})
     * @return lowercase hex-encoded {@value #HASH_ALGORITHM} digest (64 characters)
     * @throws IllegalStateException if {@value #HASH_ALGORITHM} is unexpectedly unavailable
     */
    static String hash(String code) {
        return HexFormat.of().formatHex(digestBytes(code));
    }

    /**
     * Verifies a submitted OTP code against a previously stored hash in constant time.
     * <p>
     * Hashes {@code submittedCode} and compares the resulting raw digest bytes against
     * those decoded from {@code storedHash} using {@link MessageDigest#isEqual}, which
     * runs in constant time to prevent timing-based side-channel attacks.
     * </p>
     *
     * @param submittedCode the raw OTP code entered by the user (must not be {@code null})
     * @param storedHash    the hex-encoded hash previously stored in the auth session (must not be {@code null})
     * @return {@code true} if the submitted code matches the stored hash, {@code false} otherwise
     * @throws IllegalStateException if {@value #HASH_ALGORITHM} is unexpectedly unavailable
     */
    static boolean matches(String submittedCode, String storedHash) {
        byte[] submittedBytes = digestBytes(submittedCode);
        byte[] storedBytes = HexFormat.of().parseHex(storedHash);
        return MessageDigest.isEqual(submittedBytes, storedBytes);
    }

    private static byte[] digestBytes(String code) {
        try {
            MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);
            return digest.digest(code.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(HASH_ALGORITHM + " algorithm not available", e);
        }
    }
}
