from typing import Optional

__all__ = [
    "MissingComponentsError",
    "InvaildPasswordLengthError",
    "check_passwd_requirements",
]


class MissingComponentsError(ValueError):
    def __init__(self, missing: set):
        self.missing = missing

    def __str__(self):
        return (
            f"Password is missing the necessary characters: {", ".join(self.missing)}"
        )


class InvaildPasswordLengthError(ValueError):
    def __init__(
        self,
        length: int,
        min_length: Optional[int] = None,
        max_length: Optional[int] = None,
    ):
        self.length = length
        self.min_length = min_length
        self.max_length = max_length
        assert (self.min_length and self.max_length) or (
            not self.min_length and not self.max_length
        )

    def __str__(self):

        if self.min_length and self.max_length:
            return f"Password does not meet the length requirement ({self.min_length} ~ {self.max_length})"
        else:
            return f"Password does not meet the length requirement"


def check_passwd_requirements(
    passwd: str,
    min_length: int,
    max_length: int,
    must_contain: list[str] = [],
):
    length = len(passwd)
    if not (min_length < length < max_length):
        raise InvaildPasswordLengthError(length, min_length, max_length)

    pwd_set = set(passwd)
    must_set = set(must_contain)

    if not must_set.issubset(pwd_set):
        missing = must_set - (pwd_set & must_set)
        raise MissingComponentsError(missing)
