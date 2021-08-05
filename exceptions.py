class ThemisError(Exception):
    """Base class for all themis error"""


class InvalidTriggerEvent(ThemisError):
    def __init__(self):
        msg = "event is not a aws config trigger event."
        Exception.__init__(self, msg)


class InvalidPeriodicEvent(ThemisError):
    def __init__(self):
        msg = "event is not a aws config periodic event."
        Exception.__init__(self, msg)
