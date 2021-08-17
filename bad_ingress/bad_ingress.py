import boto3
import copy
import helper
import exceptions
from core import TriggerEvent
from core import ThemisRule, ThemisEvaluator, ThemisFixer


class BadIngressRule(ThemisRule):
    def annotation(self, invalid_properties):
        invalid_ip_permissions = invalid_properties
        if not invalid_ip_permissions:
            return "compliant"
        # when there are invalid ports, add it in annotation
        annotation_ports = []
        for invalid_ip_permission in invalid_ip_permissions:
            from_port = invalid_ip_permission["fromPort"]
            to_port = invalid_ip_permission["toPort"]
            if from_port != to_port:
                annotation_ports.append(f"{from_port}-{to_port}")
            else:
                annotation_ports.append(f"{from_port}")
        return ", ".join(annotation_ports) + " opened to public"

    def invalid_properties(self, properties_to_validate):
        ip_permissions = properties_to_validate
        invalid_ip_permissions = []
        allowed_port_ranges = self.rules.get("allow_port_ranges", [])
        allowed_single_ports = self.rules.get("allowed_ports", [])
        for ip_permission in ip_permissions:
            allowed = False
            ip_ranges = helper.get_from_dict(ip_permission, "ipv4Ranges", "IpRanges")
            for cidrs in ip_ranges:
                cidr = helper.get_from_dict(cidrs, "cidrIp", "CidrIp")
                from_port = helper.get_from_dict(ip_permission, "fromPort", "FromPort")
                to_port = helper.get_from_dict(ip_permission, "toPort", "ToPort")
                if "0.0.0.0/0" == cidr:
                    if (
                        helper.get_from_dict(ip_permission, "ipProtocol", "IpProtocol")
                        == "-1"
                    ):
                        if not from_port:
                            from_port = 0
                        if not to_port:
                            to_port = 65535
                    if from_port == to_port and from_port in allowed_single_ports:
                        continue
                    # check if sg port or sg port_range is within port_ranges
                    for allowed_port_range in allowed_port_ranges:
                        allowed = (
                            allowed_port_range["from"] <= from_port
                            and to_port <= allowed_port_range["to"]
                        )
                        if allowed:
                            break
                    if not allowed or not allowed_port_ranges:
                        invalid_ip_permissions.append(ip_permission)
                        break
        return invalid_ip_permissions


class BadIngressEvaluator(ThemisEvaluator):
    def __init__(self, event, context, test_mode):
        self.test_mode = test_mode
        self.input_event = event
        self.context = context
        self.rule = BadIngressRule()

    def applicable(self):
        try:
            self.event = TriggerEvent(self.input_event, self.test_mode)
            self.event.evaluator_module = "bad_ingress"
            # only applicable for security group events
            if self.event.resource_type() != "AWS::EC2::SecurityGroup":
                return False
            # can not apply this rule for deleted sg
            if self.event.is_delete_event():
                return False
            # evaluate only when the event has only ip permissions changes on update
            if self.event.diff() is not None and self.event.is_update_event():
                for changed_property_name in (
                    self.event.diff().get("changedProperties", {}).keys()
                ):
                    return "IpPermissions" in changed_property_name
        except exceptions.InvalidTriggerEvent:
            print("the given event is not trigger event")
            return False
        print("bad_ingress is applicable")
        return True

    def handle(self):
        ip_permissions = self.event.configuration_item()["configuration"][
            "ipPermissions"
        ]
        invalid_ip_permissions = self.rule.invalid_properties(ip_permissions)
        self.event.compliant = len(invalid_ip_permissions) == 0
        self.event.annotation = self.rule.annotation(invalid_ip_permissions)
        self.event.put_evaluation()
        if (not self.event.is_first_scan()) and (self.event.compliant is False):
            self.event.notify()


class BadIngressFixer(ThemisFixer):
    def __init__(self, event, context, test_mode):
        self.test_mode = test_mode
        self.event = event
        self.context = context
        self.rule = BadIngressRule()
        self.ec2_client = boto3.resource("ec2")

    def applicable(self):
        self.security_group = self.ec2_client.SecurityGroup(self.resource_id())
        self.vpc_cidr = self.ec2_client.Vpc(self.security_group.vpc_id).cidr_block
        return True

    def modify_invalid_ingress(self, invalid_ip_permissions):
        invalid_ip_permissions_copy = copy.deepcopy(invalid_ip_permissions)
        for invalid_ip_permssion in invalid_ip_permissions_copy:
            for ip_range in invalid_ip_permssion["IpRanges"]:
                if ip_range["CidrIp"] == "0.0.0.0/0":
                    ip_range["Description"] = "modified by themis rule : bad_ingress"
                    ip_range["CidrIp"] = self.vpc_cidr
        return invalid_ip_permissions_copy

    def ip_permissions(self):
        ip_permissions = self.security_group.ip_permissions
        return ip_permissions

    def handle(self):
        invalid_ip_permissions = self.rule.invalid_properties(self.ip_permissions())
        print(f"invalid_ip_permissions: {invalid_ip_permissions}")
        modified_ingress = self.modify_invalid_ingress(invalid_ip_permissions)
        print(f"modified_ingress: {modified_ingress}")
        self.security_group.authorize_ingress(
            GroupId=self.security_group.id,
            IpPermissions=modified_ingress,
            DryRun=self.test_mode,
        )
        self.security_group.revoke_ingress(
            GroupId=self.security_group.id,
            IpPermissions=invalid_ip_permissions,
            DryRun=self.test_mode,
        )
