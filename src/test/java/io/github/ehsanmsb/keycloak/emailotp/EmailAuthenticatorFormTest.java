package io.github.ehsanmsb.keycloak.emailotp;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.EventBuilder;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionProvider;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.BruteForceProtector;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@DisplayName("EmailAuthenticatorForm Tests")
class EmailAuthenticatorFormTest {

    private EmailAuthenticatorForm authenticator;

    @BeforeEach
    void setUp() {
        authenticator = new EmailAuthenticatorForm();
    }

    @Test
    @DisplayName("Should require user")
    void testRequiresUser() {
        assertTrue(authenticator.requiresUser());
    }

    @Test
    @DisplayName("Should be configured for user with email")
    void testConfiguredForWithEmail() {
        UserModel user = mock(UserModel.class);
        when(user.getEmail()).thenReturn("user@example.com");

        assertTrue(authenticator.configuredFor(mock(KeycloakSession.class), mock(RealmModel.class), user));
    }

    @Test
    @DisplayName("Should not be configured for user without email")
    void testConfiguredForWithoutEmail() {
        UserModel user = mock(UserModel.class);
        when(user.getEmail()).thenReturn("");

        assertFalse(authenticator.configuredFor(mock(KeycloakSession.class), mock(RealmModel.class), user));
    }

    @Test
    @DisplayName("Should not register required actions")
    void testSetRequiredActionsIsNoop() {
        UserModel user = mock(UserModel.class);

        authenticator.setRequiredActions(mock(KeycloakSession.class), mock(RealmModel.class), user);

        verify(user, never()).addRequiredAction(anyString());
    }

    @Test
    @DisplayName("Should report invalid OTP to Keycloak brute-force protection")
    void testInvalidCodeReportsOtpFailure() {
        TestableForm form = new TestableForm();
        AuthenticationFlowContext context = mockContextWithSubmittedCode("000000");
        AuthenticationSessionModel session = context.getAuthenticationSession();
        RealmModel realm = context.getRealm();
        UserModel user = context.getUser();
        BruteForceProtector protector = context.getProtector();
        ClientConnection connection = context.getConnection();
        UriInfo uriInfo = context.getUriInfo();

        when(session.getAuthNote(EmailConstants.CODE)).thenReturn(OtpHashUtils.hash("123456"));
        when(session.getAuthNote(EmailConstants.CODE_TTL))
                .thenReturn(String.valueOf(System.currentTimeMillis() + 300_000));
        when(realm.isBruteForceProtected()).thenReturn(true);

        form.action(context);

        verify(protector).failedLogin(realm, user, connection, uriInfo, "otp");
        verify(context).failureChallenge(eq(AuthenticationFlowError.INVALID_CREDENTIALS), any());
    }

    @Test
    @DisplayName("Should leave OTP form and clear sessions when user becomes blocked")
    void testInvalidCodeRedirectsWhenUserBlocked() {
        TestableForm form = new TestableForm();
        AuthenticationFlowContext context = mockContextWithSubmittedCode("000000");
        AuthenticationSessionModel session = context.getAuthenticationSession();
        RealmModel realm = context.getRealm();
        UserModel user = context.getUser();
        BruteForceProtector protector = context.getProtector();
        KeycloakSession keycloakSession = context.getSession();

        when(session.getAuthNote(EmailConstants.CODE)).thenReturn(OtpHashUtils.hash("123456"));
        when(session.getAuthNote(EmailConstants.CODE_TTL))
                .thenReturn(String.valueOf(System.currentTimeMillis() + 300_000));
        when(realm.isBruteForceProtected()).thenReturn(true);
        when(protector.isTemporarilyDisabled(keycloakSession, realm, user)).thenReturn(true);

        form.action(context);

        verify(session).removeAuthNote(EmailConstants.CODE);
        verify(session).removeAuthNote(EmailConstants.CODE_TTL);
        verify(session).removeAuthNote(EmailConstants.CODE_RESEND_AVAILABLE_AFTER);
        verify(keycloakSession.sessions()).removeUserSessions(realm, user);
        verify(context).clearUser();
        verify(context).forkWithErrorMessage(any());
        verify(context, never()).failureChallenge(eq(AuthenticationFlowError.INVALID_CREDENTIALS), any());
    }

    @Test
    @DisplayName("Should reset expired code")
    void testExpiredCodeResetsCode() {
        TestableForm form = new TestableForm();
        AuthenticationFlowContext context = mockContextWithSubmittedCode("123456");
        AuthenticationSessionModel session = context.getAuthenticationSession();

        when(session.getAuthNote(EmailConstants.CODE)).thenReturn(OtpHashUtils.hash("123456"));
        when(session.getAuthNote(EmailConstants.CODE_TTL))
                .thenReturn(String.valueOf(System.currentTimeMillis() - 1_000));

        form.action(context);

        verify(session).removeAuthNote(EmailConstants.CODE);
        verify(session).removeAuthNote(EmailConstants.CODE_TTL);
        verify(session).removeAuthNote(EmailConstants.CODE_RESEND_AVAILABLE_AFTER);
        verify(context).failureChallenge(eq(AuthenticationFlowError.EXPIRED_CODE), any());
    }

    @Test
    @DisplayName("Should return blocked account message for brute-force lockout")
    void testDisabledByBruteForceError() {
        assertEquals("email-authenticator-account-blocked", new TestableForm().testDisabledByBruteForceError());
    }

    private AuthenticationFlowContext mockContextWithSubmittedCode(String submittedCode) {
        AuthenticationFlowContext context = mock(AuthenticationFlowContext.class);
        AuthenticationSessionModel session = mock(AuthenticationSessionModel.class);
        RealmModel realm = mock(RealmModel.class);
        UserModel user = mock(UserModel.class);
        KeycloakSession keycloakSession = mock(KeycloakSession.class);
        UserSessionProvider userSessionProvider = mock(UserSessionProvider.class);
        BruteForceProtector protector = mock(BruteForceProtector.class);
        ClientConnection connection = mock(ClientConnection.class);
        UriInfo uriInfo = mock(UriInfo.class);

        when(context.getSession()).thenReturn(keycloakSession);
        when(context.getAuthenticationSession()).thenReturn(session);
        when(context.getRealm()).thenReturn(realm);
        when(context.getUser()).thenReturn(user);
        when(context.getProtector()).thenReturn(protector);
        when(context.getConnection()).thenReturn(connection);
        when(context.getUriInfo()).thenReturn(uriInfo);
        when(keycloakSession.sessions()).thenReturn(userSessionProvider);

        HttpRequest httpRequest = mock(HttpRequest.class);
        MultivaluedHashMap<String, String> formData = new MultivaluedHashMap<>();
        formData.putSingle(EmailConstants.CODE, submittedCode);
        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(httpRequest.getDecodedFormParameters()).thenReturn(formData);

        EventBuilder event = mock(EventBuilder.class);
        when(context.getEvent()).thenReturn(event);
        when(event.user(any(UserModel.class))).thenReturn(event);

        AuthenticationExecutionModel execution = mock(AuthenticationExecutionModel.class);
        when(context.getExecution()).thenReturn(execution);
        when(execution.getId()).thenReturn("email-otp");

        LoginFormsProvider loginForm = mock(LoginFormsProvider.class);
        when(context.form()).thenReturn(loginForm);
        when(loginForm.setExecution(anyString())).thenReturn(loginForm);
        when(loginForm.setAttribute(anyString(), any())).thenReturn(loginForm);
        when(loginForm.addError(any())).thenReturn(loginForm);
        when(loginForm.createForm(anyString())).thenReturn(mock(Response.class));

        AuthenticatorConfigModel config = mock(AuthenticatorConfigModel.class);
        when(context.getAuthenticatorConfig()).thenReturn(config);
        when(config.getConfig()).thenReturn(Map.of());

        return context;
    }

    static class TestableForm extends EmailAuthenticatorForm {
        @Override
        public boolean enabledUser(AuthenticationFlowContext context, UserModel user) {
            return true;
        }

        String testDisabledByBruteForceError() {
            return disabledByBruteForceError("user_temporarily_disabled");
        }
    }
}
