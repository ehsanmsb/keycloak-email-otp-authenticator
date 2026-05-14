package io.github.ehsanmsb.keycloak.emailotp;

/**
 * Constants used for email-based two-factor authentication in Keycloak.
 * <p>
 * This utility class contains all configuration keys and default values
 * for the email authenticator provider.
 * </p>
 *
 * @author Mesut Pişkin
 * @version 26.1.1
 * @since 1.0.0
 */
public final class EmailConstants {

	/**
	 * Authentication session note key for storing the generated email code.
	 */
	public static final String CODE = "emailCode";

	/**
	 * Configuration key for the length of the generated code.
	 * Value should be a positive integer.
	 */
	public static final String CODE_LENGTH = "length";

	/**
	 * Configuration key for the time-to-live (TTL) of the code in seconds.
	 * After this period, the code will expire.
	 */
	public static final String CODE_TTL = "ttl";

	/**
	 * Configuration key for the cooldown period in seconds between resend requests.
	 * Users must wait this duration before requesting a new code.
	 */
	public static final String RESEND_COOLDOWN = "resendCooldown";

	/**
	 * Authentication session note key for storing the timestamp when resend becomes
	 * available.
	 */
	public static final String CODE_RESEND_AVAILABLE_AFTER = "emailCodeResendAvailableAfter";

	/**
	 * Default code length (number of digits).
	 */
	public static final int DEFAULT_LENGTH = 6;

	/**
	 * Default code TTL in seconds (5 minutes).
	 */
	public static final int DEFAULT_TTL = 300;

	/**
	 * Default resend cooldown in seconds (30 seconds).
	 */
	public static final int DEFAULT_RESEND_COOLDOWN = 30;

	/**
	 * Configuration key for overriding the OTP email subject.
	 * When blank, the plugin keeps using the localized default subject.
	 */
	public static final String EMAIL_SUBJECT = "emailSubject";

	/**
	 * Configuration key for optional text prepended to the OTP email body.
	 */
	public static final String EMAIL_INTRO_TEXT = "emailIntroText";

	/**
	 * Millisecond rounding offset used for converting milliseconds to seconds.
	 * Adding 999ms before division ensures proper ceiling rounding.
	 */
	public static final long MILLIS_ROUNDING_OFFSET = 999L;

	/**
	 * Private constructor to prevent instantiation of this utility class.
	 *
	 * @throws UnsupportedOperationException if instantiation is attempted
	 */
	private EmailConstants() {
		throw new UnsupportedOperationException("EmailConstants is a utility class and cannot be instantiated");
	}
}
