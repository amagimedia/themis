from abc import ABC, abstractmethod
import helper


class ThemisRule(ABC):
    def __init__(self):
        module_name = self.__module__.split(".")[0]  # bad_ingress.bad_ingress.py => ["bad_ingress", "bad_ingress"]
        self.rules = helper.get_rules(module_name)

    @abstractmethod
    def invalid_properties(self, properties_to_validate):
        pass

    @abstractmethod
    def annotation(self, invalid_properties):
        pass


class ThemisEvaluator(ABC):
    @abstractmethod
    def applicable(self):
        pass

    @abstractmethod
    def handle(self):
        pass


class ThemisFixer(ABC):
    @abstractmethod
    def applicable(self):
        pass

    @abstractmethod
    def handle(self):
        pass

    def resource_id(self):
        return self.event["ResourceID"]
