"""Safe, user-facing errors; messages must never contain secret values."""


class ExchangeError(Exception):
    """Base error for rejected operations."""


class ValidationError(ExchangeError):
    """Malformed input or unsupported package."""


class SignatureError(ExchangeError):
    """Sender signature did not verify."""


class RecipientError(ExchangeError):
    """Authenticated package has the wrong recipient or sender identity."""


class KeyError(ExchangeError):
    """A key could not be loaded or used."""


class AuthenticationError(ExchangeError):
    """AES-GCM authentication failed."""


class OutputError(ExchangeError):
    """An unsafe or conflicting output path was rejected."""
