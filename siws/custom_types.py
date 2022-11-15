from dateutil.parser import isoparse


class CustomDateTime(str):
    """
    ISO-8601 datetime string, meant to enable
    transitivity of deserialisation and serialisation.
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
