class NoActiveRevisionsError(RuntimeError):
    pass


class UserError(RuntimeError): ...


class UserNotActiveError(UserError): ...
