class VerificationError(Exception):
    pass


class InvalidSignature(VerificationError):
    pass


class ExpiredMessage(VerificationError):
    pass


class NotYetValidMessage(VerificationError):
    pass


class DomainMismatch(VerificationError):
    pass


class NonceMismatch(VerificationError):
    pass


class MalformedSession(VerificationError):
    def __init__(self, missing_fields):
        self.missing_fields = missing_fields
