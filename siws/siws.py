import secrets
import string
from datetime import datetime
from hashlib import sha256

from dateutil.parser import isoparse
from dateutil.tz import UTC
from ecdsa import SECP256k1, VerifyingKey
from pydantic import AnyUrl, BaseModel, Field

from siws.parsed import ABNFParsedMessage, RegExpParsedMessage
from siws.utils import build_signature, encode_defunc

ALPHANUMERICS = string.ascii_letters + string.digits


def generate_nonce() -> str:
    return "".join(secrets.choice(ALPHANUMERICS) for _ in range(11))


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


class CustomDateTime(str):
    """
    ISO-8601 datetime string, meant to enable transitivity of deserialisation and serialisation.
    """

    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not isinstance(v, str):
            raise TypeError("string required")
        cls.date = isoparse(v)
        return cls(v)


class SiwsMessage(BaseModel):
    """
    A class meant to fully encompass a Sign-in with Stacks message.
    Its utility striclty remains within formatting and compliance.
    """

    domain: str = Field(regex="^[^/?#]+$")
    address: str
    uri: AnyUrl
    issued_at: CustomDateTime
    nonce: str = Field(min_length=8)
    statement: str | None = Field(None, regex="^[^\n]+$")
    expiration_time: CustomDateTime | None = Field(None)
    not_before: CustomDateTime | None = Field(None)
    request_id: str | None = Field(None)
    resources: list[AnyUrl] = Field(None, min_items=1)

    def __init__(self, message: str | dict, abnf: bool = True):
        if isinstance(message, str):
            if abnf:
                parsed_message = ABNFParsedMessage(message=message)
            else:
                parsed_message = RegExpParsedMessage(message=message)
            message_dict = parsed_message.__dict__
        elif isinstance(message, dict):
            message_dict = message
        else:
            raise TypeError
        # There is some redundancy in the checks when deserialising a message.
        super().__init__(**message_dict)

    def prepare_message(self) -> str:
        """
        Retrieve an EIP-4361 formatted message for signature. It is recommended to instead use
        sign_message() which will resolve to the correct method based on the [type] attribute
        of this object, in case of other formats being implemented.
        :return: EIP-4361 formatted message, ready for EIP-191 signing.
        """
        header = f"{self.domain} wants you to sign in with your Stacks account:"

        uri_field = f"URI: {self.uri}"

        prefix = "\n".join([header, self.address])

        nonce_field = f"Nonce: {self.nonce}"

        suffix_array = [uri_field, nonce_field]

        if self.issued_at is None:
            # TODO: Should we default to UTC or settle for local time? UX may be better for local
            self.issued_at = datetime.now().astimezone().isoformat()

        issued_at_field = f"Issued At: {self.issued_at}"
        suffix_array.append(issued_at_field)

        if self.expiration_time:
            expiration_time_field = f"Expiration Time: {self.expiration_time}"
            suffix_array.append(expiration_time_field)

        if self.not_before:
            not_before_field = f"Not Before: {self.not_before}"
            suffix_array.append(not_before_field)

        if self.request_id:
            request_id_field = f"Request ID: {self.request_id}"
            suffix_array.append(request_id_field)

        if self.resources:
            resources_field = "\n".join(
                ["Resources:"] + [f"- {resource}" for resource in self.resources]
            )
            suffix_array.append(resources_field)

        suffix = "\n".join(suffix_array)

        if self.statement:
            prefix = "\n\n".join([prefix, self.statement])
        else:
            prefix += "\n"

        return "\n\n".join([prefix, suffix])

    def verify(
        self,
        signature: str,
        public_key: str,
        *,
        domain: str | None = None,
        nonce: str | None = None,
        timestamp: datetime | None = None,
    ) -> bool:
        message = encode_defunc(self.prepare_message())

        verification_time = datetime.now(UTC) if timestamp is None else timestamp
        if domain is not None and domain != self.domain:
            raise DomainMismatch
        elif nonce is not None and self.nonce != nonce:
            raise NonceMismatch
        elif self.expiration_time is not None and verification_time >= self.expiration_time:
            raise ExpiredMessage
        elif self.not_before is not None and verification_time <= self.not_before.date:
            raise NotYetValidMessage

        vk = VerifyingKey.from_string(
            bytearray.fromhex(public_key), curve=SECP256k1, hashfunc=sha256
        )

        parsed_signature = build_signature(signature)

        if not vk.verify(parsed_signature, message):
            raise InvalidSignature

        return True
