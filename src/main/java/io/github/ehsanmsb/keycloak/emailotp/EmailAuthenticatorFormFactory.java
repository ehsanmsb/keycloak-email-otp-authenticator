package io.github.ehsanmsb.keycloak.emailotp;

import java.util.List;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class EmailAuthenticatorFormFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "email-authenticator";
    public static final EmailAuthenticatorForm SINGLETON = new EmailAuthenticatorForm();

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Company Email OTP";
    }

    @Override
    public String getReferenceCategory() {
        return "email-otp";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Sends a one-time code to the user's email address using the realm SMTP configuration.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of(
                new ProviderConfigProperty(EmailConstants.EMAIL_SUBJECT, "Email Subject",
                        "Optional custom subject for OTP emails. Leave blank to use the localized default subject.",
                        ProviderConfigProperty.STRING_TYPE, null),
                new ProviderConfigProperty(EmailConstants.EMAIL_INTRO_TEXT, "Email Intro Text",
                        "Optional text added before the default OTP email content, for example a company security notice.",
                        ProviderConfigProperty.TEXT_TYPE, null),

                new ProviderConfigProperty(EmailConstants.CODE_LENGTH, "Code Length",
                        "The number of digits of the generated code.",
                        ProviderConfigProperty.STRING_TYPE, String.valueOf(EmailConstants.DEFAULT_LENGTH)),
                new ProviderConfigProperty(EmailConstants.CODE_TTL, "Time-to-Live (seconds)",
                        "The time to live in seconds for the code to be valid.",
                        ProviderConfigProperty.STRING_TYPE, String.valueOf(EmailConstants.DEFAULT_TTL)),
                new ProviderConfigProperty(EmailConstants.RESEND_COOLDOWN, "Resend Cooldown (seconds)",
                        "The minimum number of seconds a user must wait before requesting a new code.",
                        ProviderConfigProperty.STRING_TYPE, String.valueOf(EmailConstants.DEFAULT_RESEND_COOLDOWN)));
    }

    @Override
    public void close() {
        // NOOP
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope config) {
        // NOOP
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // NOOP
    }
}
