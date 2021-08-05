import json
import exceptions
from .config_event import AwsConfigEvent


class PeriodicEvent(AwsConfigEvent):
    def __init__(self, event: dict):
        super().__init__(event)
        self._ie = json.loads(event["invokingEvent"])
        if self._ie["messageType"] != "ScheduledNotification":
            raise exceptions.InvalidPeriodicEvent()

    def invoking_event(self):
        return self._ie
