
# NOTE - https://www.programiz.com/python-programming/user-defined-exception


class AuthenticationError(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


class Unauthenticated(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


class InvalidParameters(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


class UnhandledRequestType(Exception):
    def __init__(self, call, message='Unhandled call type'):
        self.call = call
        self.message = message
        super().__init__(self.message)


class MissingURL(Exception):
    pass


class AuthenticationTokenExpired(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


class APITokenExpired(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


class Unimplemented(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)
