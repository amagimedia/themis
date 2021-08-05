import json
import exceptions
from dateutil import parser
from .config_event import AwsConfigEvent
import helper


class TriggerEvent(AwsConfigEvent):
    def __init__(self, event: dict, test_mode):
        super().__init__(event)
        self.test_mode = test_mode
        self._ie = json.loads(event["invokingEvent"])
        self._ci = self._ie["configurationItem"]
        self._validate()
        if self.is_oversize_event():
            self.create_invoking_event_for_oversize_event()

    def _validate(self):
        if not (
            self._ie["messageType"] == "ConfigurationItemChangeNotification"
            or self._ie["messageType"] == "OversizedConfigurationItemChangeNotification"
        ):
            raise exceptions.InvalidTriggerEvent()

    def invoking_event(self):
        return self._ie

    def configuration_item(self):
        return self._ci

    def diff(self):
        return self._ie.get("configurationItemDiff")

    def create_invoking_event_for_oversize_event(self):
        ci = {}
        aws_resp = self.aws_config_client.get_resource_config_history(
            resourceType=self.resource_type(),
            resourceId=self.resource_id(),
            laterTime=self.capture_time(),
            limit=1,
        )
        resp = aws_resp["configurationItems"][0]
        ci["awsAccountId"] = resp["accountId"]
        ci["ARN"] = resp["arn"]
        ci["configurationStateMd5Hash"] = resp["configurationItemMD5Hash"]
        ci["configurationItemVersion"] = resp["version"]
        ci["configuration"] = json.loads(resp["configuration"])
        ci["relationships"] = []
        if "relationships" in resp:
            for i in range(len(resp["relationships"])):
                ci["relationships"].append({})
                ci["relationships"][i]["name"] = resp["relationships"][i]["relationshipName"]
        self._ie["configurationItem"] = ci
        self._ic = ci

    def is_oversize_event(self):
        return self._ie["messageType"] == "OversizedConfigurationItemChangeNotification"

    def resource_type(self):
        return self._ci["resourceType"]

    def resource_id(self):
        return self._ci["resourceId"]

    def arn(self):
        return self._ci["ARN"]

    def region(self):
        return self._ci.get("awsRegion")

    def capture_time(self):
        t = self._ci["configurationItemCaptureTime"]
        return parser.isoparse(t)

    def is_delete_event(self):
        if self._ie['configurationItemDiff']:
            return self._ie['configurationItemDiff']['changeType'] == 'DELETE'

    def is_create_event(self):
        if self._ie['configurationItemDiff']:
            return self._ie['configurationItemDiff']['changeType'] == "CREATE"

    def is_update_event(self):
        if self._ie['configurationItemDiff']:
            return self._ie['configurationItemDiff']['changeType'] == "UPDATE"

    def is_first_scan(self):
        return self._ie['configurationItemDiff'] is None

    def _append_to_compliance_report(self):
        c = {}
        if self.compliant is True:
            c["ComplianceType"] = "COMPLIANT"
        elif self.compliant is False:
            c["ComplianceType"] = "NON_COMPLIANT"
        elif self.compliant is None:
            c["ComplianceType"] = "NOT_APPLICABLE"
        c["Annotation"] = self.annotation
        c["ComplianceResourceId"] = self.resource_id()
        c["ComplianceResourceType"] = self.resource_type()
        c["OrderingTimestamp"] = self._ci["configurationItemCaptureTime"]
        self._compliance_report["Evaluations"].append(c)

    def _create_aws_evaluation_report(self):
        self._append_to_compliance_report()
        self._compliance_report["ResultToken"] = self.result_token()
        self._compliance_report["TestMode"] = self.test_mode

    def related_resources(self):
        related_resources = []
        if self._ci.get("relationships"):
            for related_rsrc in self._ci["relationships"]:
                related_resources.append(related_rsrc["resourceId"])
        return related_resources

    def put_evaluation(self):
        self._create_aws_evaluation_report()
        self.aws_config_client.put_evaluations(**self._compliance_report)

    def notify(self):
        msg_dict = {}
        msg_dict["account_id"] = self.account_id()
        msg_dict["resource_id"] = self.resource_id()
        msg_dict["resource_type"] = self.resource_type()
        msg_dict["region"] = self.region()
        msg_dict["notification_time"] = str(self.capture_time())
        account_alias = helper.account_alias()
        if account_alias:
            msg_dict["account_alias"] = account_alias
        msg_dict["annotation"] = self.annotation
        msg_dict["compliant"] = self.compliant
        msg_dict["rule"] = self.evaluator_module
        msg_dict["related_resources"] = ",".join(self.related_resources())
        msg = helper.convert_dict_to_html_table(msg_dict, self.compliant)
        sub = f"themis alert for aws account {account_alias or self.account_id()}"
        helper.send_email(sub, msg)
