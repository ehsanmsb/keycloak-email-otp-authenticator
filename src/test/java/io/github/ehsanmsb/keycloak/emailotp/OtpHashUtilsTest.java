package io.github.ehsanmsb.keycloak.emailotp;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("OtpHashUtils Tests")
class OtpHashUtilsTest {

    @Test
    @DisplayName("Same input always produces the same hash")
    void testDeterministic() {
        assertEquals(OtpHashUtils.hash("123456"), OtpHashUtils.hash("123456"));
    }

    @Test
    @DisplayName("Different inputs produce different hashes")
    void testCollisionResistance() {
        assertNotEquals(OtpHashUtils.hash("123456"), OtpHashUtils.hash("654321"));
    }

    @Test
    @DisplayName("Hash is never equal to the raw code")
    void testHashDoesNotLeakRawCode() {
        String code = "123456";
        assertNotEquals(code, OtpHashUtils.hash(code));
    }

    @Test
    @DisplayName("matches returns true for correct code against its stored hash")
    void testMatchesCorrectCode() {
        String code = "123456";
        assertTrue(OtpHashUtils.matches(code, OtpHashUtils.hash(code)));
    }

    @Test
    @DisplayName("matches returns false for wrong code against stored hash")
    void testMatchesWrongCode() {
        assertFalse(OtpHashUtils.matches("654321", OtpHashUtils.hash("123456")));
    }
}
