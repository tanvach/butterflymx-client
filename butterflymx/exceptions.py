"""Exceptions raised by the ButterflyMX client."""


class ButterflyMXError(Exception):
    """Base class for all ButterflyMX client errors."""


class ButterflyMXAuthError(ButterflyMXError):
    """Login failed or the account's tokens were rejected.

    Usually means a wrong email/password, or the session was revoked.
    Retrying won't help until the credentials are fixed.
    """


class ButterflyMXVerificationRequired(ButterflyMXAuthError):
    """The password was submitted, but ButterflyMX asked for a verification code.

    Two-step verification (an SMS or authenticator code) is not supported.
    This is a subclass of ButterflyMXAuthError, so existing callers that only
    catch that still treat it as a failed login. Catch this type first to tell
    it apart from a wrong password.
    """


class ButterflyMXConnectionError(ButterflyMXError):
    """Couldn't reach ButterflyMX: network error, timeout, or a 5xx response.

    Usually temporary; safe to retry later.
    """


class ButterflyMXApiError(ButterflyMXError):
    """ButterflyMX returned something unexpected (GraphQL errors, unexpected
    status codes, or a changed login page)."""
