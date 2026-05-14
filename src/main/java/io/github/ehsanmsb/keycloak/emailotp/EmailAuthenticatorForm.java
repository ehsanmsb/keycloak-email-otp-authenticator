package io.github.ehsanmsb.keycloak.emailotp;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationFlowException;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.models.AuthenticatorConfigModel;

import org.jboss.logging.Logger;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import java.util.HashMap;
import java.util.Map;

/**
 * Keycloak authenticator that implements two-factor authentication via email.
 * <p>
 * This authenticator generates a one-time password (OTP) and sends it to the
 * user's
 * registered email address. The user must enter the received code to complete
 * authentication.
 * </p>
 * <p>
 * Features include:
 * <ul>
 * <li>Configurable code length and TTL (time-to-live)</li>
 * <li>Resend cooldown to prevent spam</li>
 * <li>Keycloak brute-force protection support</li>
 * <li>Code expiration handling</li>
 * </ul>
 * </p>
 *
 * @author Mesut Pişkin
 * @version 26.1.1
 * @since 1.0.0
 */
public class EmailAuthenticatorForm extends AbstractUsernameFormAuthenticator {

    protected static final Logger logger = Logger.getLogger(EmailAuthenticatorForm.class);
    private static final String OTP_AUTHENTICATION_CATEGORY = "otp";

    /**
     * Initiates the authentication process by presenting the email OTP challenge to
     * the user.
     * <p>
     * This method is called by Keycloak when the user reaches this authenticator in
     * the flow.
     * It generates and sends an email code, then displays the form for code entry.
     * </p>
     *
     * @param context the authentication flow context containing user, session, and
     *                realm information
     */
    @Override
    public void authenticate(AuthenticationFlowContext context) {
        context.challenge(challenge(context, null));
    }

    /**
     * Creates the authentication challenge response with the email code entry form.
     * <p>
     * Generates and sends the email code if not already sent, prepares the form
     * with
     * any error messages, and returns the rendered form response.
     * </p>
     *
     * @param context the authentication flow context
     * @param error   optional error message key to display
     * @param field   optional field name associated with the error
     * @return the HTTP response containing the rendered form
     */
    @Override
    protected Response challenge(AuthenticationFlowContext context, String error, String field) {
        generateAndSendEmailCode(context);
        LoginFormsProvider form = prepareForm(context, null);
        applyFormMessage(form, error, field);
        return form.createForm("email-code-form.ftl");
    }

    /**
     * Generates a random email code and sends it to the user's registered email
     * address.
     * <p>
     * If a code has already been generated for this session, this method returns
     * early
     * to prevent duplicate emails. The code is stored in the authentication session
     * along
     * with its expiration time and resend cooldown period.
     * </p>
     *
     * @param context the authentication flow context
     */
    private void generateAndSendEmailCode(AuthenticationFlowContext context) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        AuthenticationSessionModel session = context.getAuthenticationSession();

        if (session.getAuthNote(EmailConstants.CODE) != null) {
            // skip sending email code
            return;
        }

        Map<String, String> configValues = config != null && config.getConfig() != null
                ? config.getConfig()
                : Map.of();

        int length = resolvePositiveInt(configValues, EmailConstants.CODE_LENGTH, EmailConstants.DEFAULT_LENGTH);
        int ttl = resolvePositiveInt(configValues, EmailConstants.CODE_TTL, EmailConstants.DEFAULT_TTL);
        int resendCooldown = resolvePositiveInt(configValues, EmailConstants.RESEND_COOLDOWN,
                EmailConstants.DEFAULT_RESEND_COOLDOWN);

        String code = SecretGenerator.getInstance().randomString(length, SecretGenerator.DIGITS);
        sendEmailWithCode(context, code, ttl);

        session.setAuthNote(EmailConstants.CODE, OtpHashUtils.hash(code));
        long now = System.currentTimeMillis();
        session.setAuthNote(EmailConstants.CODE_TTL, Long.toString(now + (ttl * 1000L)));
        session.setAuthNote(EmailConstants.CODE_RESEND_AVAILABLE_AFTER, Long.toString(now + (resendCooldown * 1000L)));
    }

    /**
     * Resolves a positive integer configuration value with validation and fallback.
     * <p>
     * Parses the configuration value for the given key. If the value is missing,
     * blank,
     * not a valid integer, or non-positive, returns the default value and logs a
     * warning.
     * </p>
     *
     * @param configValues the configuration map
     * @param key          the configuration key to resolve
     * @param defaultValue the fallback value if parsing fails or value is invalid
     * @return the parsed positive integer or the default value
     */
    private int resolvePositiveInt(Map<String, String> configValues, String key, int defaultValue) {
        String raw = configValues.get(key);
        if (raw == null || raw.isBlank()) {
            return defaultValue;
        }
        try {
            int parsed = Integer.parseInt(raw.trim());
            if (parsed <= 0) {
                logger.warnf("Configuration value for %s was non-positive ('%s'); falling back to default %d", key, raw,
                        defaultValue);
                return defaultValue;
            }
            return parsed;
        } catch (NumberFormatException ex) {
            logger.warnf("Configuration value for %s was invalid ('%s'); falling back to default %d", key, raw,
                    defaultValue);
            return defaultValue;
        }
    }

    /**
     * Processes the form submission when the user enters the email code.
     * <p>
     * Validates the submitted code against the stored code, checking for expiration
     * and correctness. Handles special form actions like "resend" and "cancel".
     * On successful validation, marks the authentication as successful.
     * </p>
     *
     * @param context the authentication flow context
     */
    @Override
    public void action(AuthenticationFlowContext context) {
        UserModel userModel = context.getUser();
        if (!enabledUser(context, userModel)) {
            // error in context is set in enabledUser/isDisabledByBruteForce
            return;
        }

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        if (handleFormShortcuts(context, formData)) {
            return;
        }

        if (isValidCodeContext(context, userModel, formData)) {
            resetEmailCode(context);
            context.success();
        }
    }

    private boolean handleFormShortcuts(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        if (formData.containsKey("resend")) {
            AuthenticationSessionModel session = context.getAuthenticationSession();
            Long remainingSeconds = getRemainingSeconds(session);
            if (remainingSeconds != null && remainingSeconds > 0L) {
                LoginFormsProvider form = prepareForm(context, remainingSeconds);
                applyFormMessage(form, "email-authenticator-resend-cooldown", null, remainingSeconds);
                context.challenge(form.createForm("email-code-form.ftl"));
                return true;
            }

            resetEmailCode(context);
            context.challenge(challenge(context, null));
            return true;
        }

        if (formData.containsKey("cancel")) {
            resetEmailCode(context);
            context.resetFlow();
            return true;
        }

        return false;
    }

    private record CodeContext(String storedCode, Long expiresAt, String submittedCode) {
    }

    private CodeContext buildCodeContext(AuthenticationSessionModel session, MultivaluedMap<String, String> formData) {
        String storedCode = session.getAuthNote(EmailConstants.CODE);
        String ttlNote = session.getAuthNote(EmailConstants.CODE_TTL);
        Long expiresAt = null;
        if (ttlNote != null) {
            try {
                expiresAt = Long.parseLong(ttlNote);
            } catch (NumberFormatException ex) {
                logger.warnf("Invalid TTL value '%s' found for email authenticator; treating as expired", ttlNote);
            }
        }

        String submittedRaw = formData.getFirst(EmailConstants.CODE);
        String submittedCode = submittedRaw == null ? null : submittedRaw.strip();

        return new CodeContext(storedCode, expiresAt, submittedCode);
    }

    private boolean isValidCodeContext(AuthenticationFlowContext context, UserModel user,
            MultivaluedMap<String, String> formData) {
        CodeContext codeContext = buildCodeContext(context.getAuthenticationSession(), formData);
        if (codeContext.storedCode() == null || codeContext.expiresAt() == null) {
            context.getEvent().user(user).error(Errors.INVALID_USER_CREDENTIALS);
            Response challengeResponse = challenge(context, Messages.INVALID_ACCESS_CODE, EmailConstants.CODE);
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challengeResponse);
            return false;
        }

        if (codeContext.submittedCode() == null || codeContext.submittedCode().isEmpty()) {
            context.challenge(challenge(context, Messages.MISSING_TOTP, EmailConstants.CODE));
            return false;
        }

        if (codeContext.expiresAt() < System.currentTimeMillis()) {
            resetEmailCode(context);
            context.getEvent().user(user).error(Errors.EXPIRED_CODE);
            Response challengeResponse = challenge(context, Messages.EXPIRED_ACTION_TOKEN_SESSION_EXISTS,
                    EmailConstants.CODE);
            context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE, challengeResponse);
            return false;
        }

        if (OtpHashUtils.matches(codeContext.submittedCode(), codeContext.storedCode())) {
            return true;
        }

        context.getEvent().user(user).error(Errors.INVALID_USER_CREDENTIALS);

        // Let Keycloak be the single source of truth for lockout thresholds.
        // The category must be "otp" so modern Keycloak counts it as a
        // secondary-authentication failure.
        recordBruteForceFailure(context, user);
        Response challengeResponse = challenge(context, Messages.INVALID_ACCESS_CODE, EmailConstants.CODE);
        context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challengeResponse);
        return false;
    }

    private void recordBruteForceFailure(AuthenticationFlowContext context, UserModel user) {
        if (context.getRealm().isBruteForceProtected() && context.getProtector() != null) {
            context.getProtector().failedLogin(
                    context.getRealm(),
                    user,
                    context.getConnection(),
                    context.getUriInfo(),
                    OTP_AUTHENTICATION_CATEGORY);
        }
    }

    private LoginFormsProvider prepareForm(AuthenticationFlowContext context, Long remainingSeconds) {
        AuthenticationSessionModel session = context.getAuthenticationSession();
        LoginFormsProvider form = context.form().setExecution(context.getExecution().getId());
        Long secondsToExpose = remainingSeconds != null ? remainingSeconds : getRemainingSeconds(session);
        if (secondsToExpose != null && secondsToExpose > 0L)
            form.setAttribute("resendAvailableInSeconds", secondsToExpose);

        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        Map<String, String> configValues = config != null && config.getConfig() != null
                ? config.getConfig()
                : Map.of();
        int codeLength = resolvePositiveInt(configValues, EmailConstants.CODE_LENGTH, EmailConstants.DEFAULT_LENGTH);
        form.setAttribute("codeLength", codeLength);

        return form;
    }

    private Long getRemainingSeconds(AuthenticationSessionModel session) {
        String rawResendAfter = session.getAuthNote(EmailConstants.CODE_RESEND_AVAILABLE_AFTER);
        if (rawResendAfter == null) {
            return null;
        }
        Long resendAt = null;
        try {
            resendAt = Long.parseLong(rawResendAfter);
        } catch (NumberFormatException ex) {
            logger.warnf("Invalid resend availability timestamp '%s' for email authenticator; allowing resend",
                    rawResendAfter);
            session.removeAuthNote(EmailConstants.CODE_RESEND_AVAILABLE_AFTER);
            return null;
        }
        long remainingMillis = resendAt - System.currentTimeMillis();
        return Math.max(0L, (remainingMillis + EmailConstants.MILLIS_ROUNDING_OFFSET) / 1000L);
    }

    private void applyFormMessage(LoginFormsProvider form, String messageKey, String field, Object... messageParams) {
        if (messageKey == null) {
            return;
        }
        if (field != null) {
            form.addError(new FormMessage(field, messageKey, messageParams));
        } else {
            form.setError(messageKey, messageParams);
        }
    }

    protected String disabledByBruteForceError() {
        return "email-authenticator-account-blocked";
    }

    private void resetEmailCode(AuthenticationFlowContext context) {
        AuthenticationSessionModel session = context.getAuthenticationSession();
        session.removeAuthNote(EmailConstants.CODE);
        session.removeAuthNote(EmailConstants.CODE_TTL);
        session.removeAuthNote(EmailConstants.CODE_RESEND_AVAILABLE_AFTER);
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        // Do not force a credential-enrollment detour before email OTP. In an
        // enforced browser flow, the user's email address is the configuration
        // source, so first login can go straight from password form to OTP form.
        return user != null && user.getEmail() != null && !user.getEmail().isBlank();
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // No enrollment step is required. Company deployments enforce this
        // authenticator in the browser flow for users that already have email.
    }

    @Override
    public void close() {
        // NOOP
    }

    private void sendEmailWithCode(AuthenticationFlowContext context, String code, int ttl) {
        KeycloakSession session = context.getSession();
        RealmModel realm = context.getRealm();
        UserModel user = context.getUser();

        if (user.getEmail() == null) {
            logger.warnf("Could not send access code email due to missing email. realm=%s user=%s", realm.getId(),
                    user.getUsername());
            throw new AuthenticationFlowException(AuthenticationFlowError.INVALID_USER);
        }

        // Build email message with template data. Optional subject/body
        // customizations are execution config, so they can differ by flow.
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        Map<String, String> configMap = config != null && config.getConfig() != null
                ? config.getConfig()
                : Map.of();
        Map<String, Object> templateData = new HashMap<>();
        templateData.put("username", user.getUsername());
        templateData.put("code", code);
        templateData.put("ttl", ttl);
        putEmailCustomization(templateData, configMap);

        String realmName = realm.getDisplayName() != null ? realm.getDisplayName() : realm.getName();
        String customSubject = trimToNull(configMap.get(EmailConstants.EMAIL_SUBJECT));
        String subjectKey = customSubject != null ? "emailCodeCustomSubject" : "emailCodeSubject";
        java.util.List<Object> subjectParams = java.util.List.of(customSubject != null ? customSubject : realmName);

        try {
            EmailTemplateProvider emailProvider = session.getProvider(EmailTemplateProvider.class);
            emailProvider.setRealm(realm);
            emailProvider.setUser(user);
            emailProvider.send(subjectKey, subjectParams, "code-email.ftl", templateData);
            logger.infof("Email OTP sent to %s for user %s", user.getEmail(), user.getUsername());
        } catch (EmailException e) {
            logger.errorf(e, "Failed to send email OTP. realm=%s user=%s", realm.getId(), user.getUsername());
            throw new AuthenticationFlowException(e, AuthenticationFlowError.INTERNAL_ERROR);
        }
    }

    private void putEmailCustomization(Map<String, Object> templateData, Map<String, String> configMap) {
        String introText = trimToNull(configMap.get(EmailConstants.EMAIL_INTRO_TEXT));
        if (introText != null) {
            templateData.put("emailIntroText", introText);
        }

        String customSubject = trimToNull(configMap.get(EmailConstants.EMAIL_SUBJECT));
        if (customSubject != null) {
            templateData.put("customEmailSubject", customSubject);
        }
    }
    private String trimToNull(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.trim();
    }
}
