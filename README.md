# Keycloak Email OTP Authenticator

A small Keycloak authenticator for company-managed email OTP as a second factor.

This provider intentionally uses only Keycloak's built-in realm SMTP configuration.

## Features

- Sends a one-time code to the user's configured email address after password login
- Uses Keycloak SMTP settings from `Realm settings -> Email`
- Supports configurable code length, code TTL, resend cooldown, email subject, and intro text
- Hashes OTP values in the authentication session
- Clears OTP values after success or expiration
- Reports invalid OTP submissions to Keycloak brute-force protection using the `otp` authentication category
- Compatible with modern Keycloak 26.x provider loading

## Build

```bash
mvn clean package
```

The provider jar is created at:

```text
target/keycloak-email-otp-authenticator-v<version>.jar
```

## Install

Copy the jar into Keycloak's providers directory:

```bash
cp target/keycloak-email-otp-authenticator-v<version>.jar <KEYCLOAK_HOME>/providers/
```

Then rebuild or restart Keycloak:

```bash
<KEYCLOAK_HOME>/bin/kc.sh build
<KEYCLOAK_HOME>/bin/kc.sh start
```

For local development:

```bash
<KEYCLOAK_HOME>/bin/kc.sh start-dev
```

## Configure Keycloak

1. Configure SMTP in `Realm settings -> Email`.
2. Go to `Authentication -> Flows`.
3. Copy the browser flow.
4. Add the `Company Email OTP` execution after the username/password form.
5. Set the execution requirement to `REQUIRED`.
6. Bind the copied flow in `Realm settings -> Login -> Browser flow`.

Use a private browser window or log out fully when testing, because Keycloak's cookie execution can reuse an existing SSO session.

## Authenticator Options

- `Email Subject`: optional custom subject. Blank uses the localized default subject.
- `Email Intro Text`: optional text prepended to the default OTP email body.
- `Code Length`: number of OTP digits. Default: `6`.
- `Time-to-Live (seconds)`: OTP lifetime. Default: `300`.
- `Resend Cooldown (seconds)`: minimum delay before sending another code. Default: `30`.

## Brute-Force Protection

Enable Keycloak brute-force protection in the realm. Invalid OTP submissions are reported with authentication category `otp`, so Keycloak's secondary authentication failure settings apply.

Useful realm settings:

- `Brute Force Detection`
- `Max secondary auth failures`
- `Permanent lockout`
- wait/increment lockout settings

## Local Email Testing

Mailpit is a convenient local SMTP sink:

```bash
docker run --rm --name mailpit -p 1025:1025 -p 8025:8025 axllent/mailpit
```

Configure Keycloak SMTP:

- Host: `127.0.0.1`
- Port: `1025`
- From: `noreply@example.test`
- Authentication: disabled

Open Mailpit at:

```text
http://127.0.0.1:8025
```

## Releases

Pull requests are validated with GitHub Actions. After a pull request is merged into `main`, the release workflow uses Conventional Commit messages to determine the next semantic version:

- `fix:` creates a patch release.
- `feat:` creates a minor release.
- commits with `!` or `BREAKING CHANGE:` create a major release.

The workflow creates a Git tag, creates a GitHub release, builds the provider with the release version, and uploads the generated jar to the release assets.

## License

Apache License 2.0
