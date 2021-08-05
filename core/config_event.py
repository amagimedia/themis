import boto3
from abc import ABC, abstractmethod
import helper

"""
sample events => https://docs.aws.amazon.com/config/latest/developerguide/evaluate-config_develop-rules_example-events.html
"""


class AwsConfigEvent(ABC):
    def __init__(self, event: dict):
        self._compliance_report = {}
        self._compliance_report["Evaluations"] = []
        self.compliant = None
        self.annotation = None
        self.evaluator_module = None
        self._event = event
        self.aws_config_client = boto3.client("config")

    @abstractmethod
    def invoking_event(self):
        pass

    @abstractmethod
    def put_evaluation(self):
        pass

    @abstractmethod
    def capture_time(self):
        pass

    def rule_parameters(self):
        return self._event.get("ruleParameters")

    def account_id(self):
        return self._event["accountId"]

    def rule_name(self):
        return self._event["configRuleName"]

    def rule_id(self):
        return self._event["configRuleId"]

    def result_token(self):
        return self._event["resultToken"]

    def event_left_scope(self):
        return self._event["eventLeftScope"]

    def execution_role_arn(self):
        return self._event["executionRoleArn"]

    def config_rule_arn(self):
        return self._event["configRuleArn"]


