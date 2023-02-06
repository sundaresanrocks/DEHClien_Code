

class AlarmManagerException(Exception):
    def __init__(self, message):
        super(AlarmManagerException, self).__init__(message)


class ConnectionClosed(AlarmManagerException):
    def __init__(self, message):
        super(ConnectionClosed, self).__init__(message)


class InvalidAlarm(AlarmManagerException):
    def __init__(self, message):
        super(InvalidAlarm, self).__init__(message)


class AuthenticationError(AlarmManagerException):
    def __init__(self, message):
        super(AuthenticationError, self).__init__(message)
