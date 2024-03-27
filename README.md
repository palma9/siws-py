# Sign-In with Stacks

This package provides a Python adaptation of EIP-4361: Sign In With Ethereum to Stacks ecosystem.

## Usage

SIWS provides a `SiwsMessage` class.

### Parsing a SIWS Message

Parsing is done by initializing a `SiwsMessage` object with an EIP-4361 formatted string:

``` python
from siws import SiwsMessage
message: SiwsMessage = SiwsMessage(message=eip_4361_string)
```

Alternatively, initialization of a `SiwsMessage` object can be done with a dictionary containing expected attributes:

``` python
message: SiwsMessage = SiwsMessage(message={"domain": "login.xyz", "address": "SP3...", ...})
```

### Verifying and Authenticating a SIWS Message

Verification and authentication is performed, using the `address` field of the `SiwsMessage` as the expected signer. The validate method checks message structural integrity, signature address validity, and time-based validity attributes.

``` python
message.verify(signature="...", public_key="...")
```

### Serialization of a SIWS Message

`SiwsMessage` instances can also be serialized as a string representations via the `prepare_message` method:

``` python
print(message.prepare_message())
```

## Example

Parsing and verifying a `SiwsMessage` is easy:

``` python
try:
    message: SiwsMessage = SiwsMessage(message=eip_4361_string)
    message.verify(signature, public_key, nonce="abcdef", domain="example.com"):
except siws.ValueError:
    # Invalid message
    print("Authentication attempt rejected.")
except siws.ExpiredMessage:
    print("Authentication attempt rejected.")
except siws.DomainMismatch:
    print("Authentication attempt rejected.")
except siws.NonceMismatch:
    print("Authentication attempt rejected.")
except siws.MalformedSession as e:
    # e.missing_fields contains the missing information needed for validation
    print("Authentication attempt rejected.")
except siws.InvalidSignature:
    print("Authentication attempt rejected.")

# Message has been verified. Authentication complete. Continue with authorization/other.
```