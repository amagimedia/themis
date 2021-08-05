import unittest
from bad_ingress.bad_ingress import BadIngressRule, BadIngressEvaluator, BadIngressFixer
from unittest import mock
import json
import copy

restricted_all_port_permission = json.loads("""
                    {
                        "ipProtocol": "-1",
                        "ipv6Ranges": [],
                        "prefixListIds": [],
                        "userIdGroupPairs": [
                            {
                                "groupId": "sg-xxxxxxxxx",
                                "userId": "123456789012"
                            }
                        ],
                        "ipv4Ranges": [],
                        "ipRanges": []
                    }
""")

all_port_permission = json.loads("""
                    {
                        "ipProtocol": "-1",
                        "ipv6Ranges": [],
                        "prefixListIds": [],
                        "userIdGroupPairs": [
                            {
                                "groupId": "sg-xxxxxxxxxx",
                                "userId": "123456789012"
                            }
                        ],
                        "ipv4Ranges": [{"cidrIp": "0.0.0.0/0"}],
                        "ipRanges": ["0.0.0.0/0"]
                    }
""")

not_allowed_port = json.loads("""
                    {
                        "fromPort": 22,
                        "ipProtocol": "tcp",
                        "ipv6Ranges": [
                            {
                                "cidrIpv6": "::/0",
                                "description": "Allow SSH access"
                            }
                        ],
                        "prefixListIds": [],
                        "toPort": 22,
                        "userIdGroupPairs": [],
                        "ipv4Ranges": [
                            {
                                "cidrIp": "0.0.0.0/0",
                                "description": "Allow SSH access"
                            }
                        ],
                        "ipRanges": [
                            "0.0.0.0/0"
                        ]
                    }
""")

allowed_port = json.loads("""
                    {
                        "fromPort": 443,
                        "ipProtocol": "tcp",
                        "ipv6Ranges": [],
                        "prefixListIds": [],
                        "toPort": 443,
                        "userIdGroupPairs": [],
                        "ipv4Ranges": [
                            {
                                "cidrIp": "0.0.0.0/0",
                                "description": "Allow https access"
                            }
                        ],
                        "ipRanges": ["0.0.0.0/0"]
                    }
""")

private_port = json.loads("""
                    {
                        "fromPort": 1025,
                        "ipProtocol": "tcp",
                        "ipv6Ranges": [],
                        "prefixListIds": [],
                        "toPort": 65535,
                        "userIdGroupPairs": [
                            {
                                "description": "opening random port",
                                "groupId": "sg-xxxxxxxxx",
                                "userId": "123456789012"
                            }
                        ],
                        "ipv4Ranges": [
                            {
                                "cidrIp": "1.2.3.4/32",
                                "description": "Allow random port"
                            }
                        ],
                        "ipRanges": []
                    }
""")

port_range_within_allowed_range = json.loads("""
                    {
                        "fromPort": 3000,
                        "ipProtocol": "tcp",
                        "ipv6Ranges": [],
                        "prefixListIds": [],
                        "toPort": 4000,
                        "userIdGroupPairs": [],
                        "ipv4Ranges": [
                            {
                                "cidrIp": "0.0.0.0/0",
                                "description": "Allow random port"
                            }
                        ],
                        "ipRanges": []
                    }
""")

port_range_above_allowed_range = json.loads("""
                    {
                        "fromPort": 4500,
                        "ipProtocol": "tcp",
                        "ipv6Ranges": [],
                        "prefixListIds": [],
                        "toPort": 5001,
                        "userIdGroupPairs": [],
                        "ipv4Ranges": [
                            {
                                "cidrIp": "0.0.0.0/0",
                                "description": "Allow random port"
                            }
                        ],
                        "ipRanges": []
                    }
""")

port_range_below_allowed_range = json.loads("""
                    {
                        "fromPort": 2500,
                        "ipProtocol": "tcp",
                        "ipv6Ranges": [],
                        "prefixListIds": [],
                        "toPort": 5001,
                        "userIdGroupPairs": [],
                        "ipv4Ranges": [
                            {
                                "cidrIp": "0.0.0.0/0",
                                "description": "Allow random port"
                            }
                        ],
                        "ipRanges": []
                    }
""")

port_within_allowed_range = json.loads("""
                    {
                        "fromPort": 4500,
                        "ipProtocol": "tcp",
                        "ipv6Ranges": [],
                        "prefixListIds": [],
                        "toPort": 4500,
                        "userIdGroupPairs": [],
                        "ipv4Ranges": [
                            {
                                "cidrIp": "0.0.0.0/0",
                                "description": "Allow random"
                            }
                        ],
                        "ipRanges": []
                    }
""")


ip_permissions = [
            all_port_permission,
            restricted_all_port_permission,
            not_allowed_port,
            allowed_port,
            private_port,
            port_range_within_allowed_range,
            port_range_above_allowed_range,
            port_range_below_allowed_range,
            port_within_allowed_range
]


class TestThemisRule(unittest.TestCase):

    @mock.patch('helper.get_rules')
    def test_empty_rules_should_return_all_public_ports(self, mock_helper):
        mock_helper.return_value = {}
        bad_ingress_rule = BadIngressRule()
        expected_invalid_properties = [
            all_port_permission,
            not_allowed_port,
            allowed_port,
            port_range_within_allowed_range,
            port_range_above_allowed_range,
            port_range_below_allowed_range,
            port_within_allowed_range
        ]
        invalid_properties = bad_ingress_rule.invalid_properties(ip_permissions)
        self.assertEqual(invalid_properties, expected_invalid_properties)

    @mock.patch('helper.get_rules')
    def test_rules_should_not_return_allowed_public_ports(self, mock_helper):
        mock_helper.return_value = {
            "allowed_ports": [
                80,
                443
            ]
        }
        bad_ingress_rule = BadIngressRule()
        _ip_permissions = [allowed_port]
        expected_invalid_properties = []
        invalid_properties = bad_ingress_rule.invalid_properties(_ip_permissions)
        self.assertEqual(expected_invalid_properties, invalid_properties)

    @mock.patch('helper.get_rules')
    def test_rules_should_not_return_port_within_allowed_port_range(self, mock_helper):
        mock_helper.return_value = {
            "allowed_ports": [
                80,
                443
            ],
            "allow_port_ranges": [
                {
                    "from": 3000,
                    "to": 5000
                }
            ]
        }
        bad_ingress_rule = BadIngressRule()
        _ip_permissions = [port_within_allowed_range]
        expected_invalid_properties = []
        invalid_properties = bad_ingress_rule.invalid_properties(_ip_permissions)
        self.assertEqual(expected_invalid_properties, invalid_properties)

    @mock.patch('helper.get_rules')
    def test_rules_should_not_return_allowed_port_range(self, mock_helper):
        mock_helper.return_value = {
            "allowed_ports": [
                80,
                443
            ],
            "allow_port_ranges": [
                {
                    "from": 3000,
                    "to": 5000
                }
            ]
        }
        bad_ingress_rule = BadIngressRule()
        _ip_permissions = [port_range_within_allowed_range]
        expected_invalid_properties = []
        invalid_properties = bad_ingress_rule.invalid_properties(_ip_permissions)
        self.assertEqual(expected_invalid_properties, invalid_properties)

    @mock.patch('helper.get_rules')
    def test_rules_should_return_port_range_above_allowed_port_range(self, mock_helper):
        mock_helper.return_value = {
            "allowed_ports": [
                80,
                443
            ],
            "allow_port_ranges": [
                {
                    "from": 3000,
                    "to": 5000
                }
            ]
        }
        bad_ingress_rule = BadIngressRule()
        _ip_permissions = [port_range_above_allowed_range]
        expected_invalid_properties = [port_range_above_allowed_range]
        invalid_properties = bad_ingress_rule.invalid_properties(_ip_permissions)
        self.assertEqual(expected_invalid_properties, invalid_properties)

    @mock.patch('helper.get_rules')
    def test_rules_should_return_port_range_below_allowed_port_range(self, mock_helper):
        mock_helper.return_value = {
            "allowed_ports": [
                80,
                443
            ],
            "allow_port_ranges": [
                {
                    "from": 3000,
                    "to": 5000
                }
            ]
        }
        bad_ingress_rule = BadIngressRule()
        _ip_permissions = [port_range_below_allowed_range]
        expected_invalid_properties = [port_range_below_allowed_range]
        invalid_properties = bad_ingress_rule.invalid_properties(_ip_permissions)
        self.assertEqual(expected_invalid_properties, invalid_properties)

    @mock.patch('helper.get_rules')
    def test_all_ip_permissions(self, mock_helper):
        mock_helper.return_value = {
            "allowed_ports": [
                80,
                443
            ],
            "allow_port_ranges": [
                {
                    "from": 3000,
                    "to": 5000
                }
            ]
        }
        bad_ingress_rule = BadIngressRule()
        expected_invalid_properties = [
                    all_port_permission,
                    not_allowed_port,
                    port_range_above_allowed_range,
                    port_range_below_allowed_range,
        ]
        invalid_properties = bad_ingress_rule.invalid_properties(ip_permissions)
        self.assertEqual(expected_invalid_properties, invalid_properties)


invoking_event = {'configurationItemDiff': {'changedProperties': {'Configuration.IpPermissions.1': {'previousValue': None,
    'updatedValue': {'ipProtocol': '-1',
     'ipv6Ranges': [],
     'prefixListIds': [],
     'userIdGroupPairs': [{'groupId': 'sg-xxxxxxxxxxx',
       'userId': '1234354545'}],
     'ipv4Ranges': [],
     'ipRanges': []},
    'changeType': 'CREATE'},
   'Configuration.IpPermissions.0': {'previousValue': {'ipProtocol': '-1',
     'ipv6Ranges': [],
     'prefixListIds': [],
     'userIdGroupPairs': [{'groupId': 'sg-xxxxxxxxxxx',
       'userId': '1234354545'}],
     'ipv4Ranges': [{'cidrIp': '1.2.3.4/32'}],
     'ipRanges': ['1.2.3.4/32']},
    'updatedValue': None,
    'changeType': 'DELETE'}},
  'changeType': 'UPDATE'},
 'configurationItem': {'relatedEvents': [],
  'relationships': [{'resourceId': 'vpc-xxxxxxx',
    'resourceName': None,
    'resourceType': 'AWS::EC2::VPC',
    'name': 'Is contained in Vpc'}],
  'configuration': {'description': 'themis test',
   'groupName': 'test-themis',
   'ipPermissions': [{'ipProtocol': '-1',
     'ipv6Ranges': [],
     'prefixListIds': [],
     'userIdGroupPairs': [{'groupId': 'sg-xxxxxxxxxxxx',
       'userId': '123456789012'}],
     'ipv4Ranges': [],
     'ipRanges': []}],
   'ownerId': '123456789012',
   'groupId': 'sg-xxxxxxxxxxxx',
   'ipPermissionsEgress': [{'ipProtocol': '-1',
     'ipv6Ranges': [],
     'prefixListIds': [],
     'userIdGroupPairs': [],
     'ipv4Ranges': [{'cidrIp': '0.0.0.0/0'}],
     'ipRanges': ['0.0.0.0/0']}],
   'tags': [],
   'vpcId': 'vpc-xxxxxxxxx'},
  'supplementaryConfiguration': {},
  'tags': {},
  'configurationItemVersion': '1.3',
  'configurationItemCaptureTime': '2021-06-29T10:53:43.935Z',
  'configurationStateId': 1234567821412,
  'awsAccountId': '123456789012',
  'configurationItemStatus': 'OK',
  'resourceType': 'AWS::EC2::SecurityGroup',
  'resourceId': 'sg-xxxxxxxxxxxx',
  'resourceName': 'test-themis',
  'ARN': 'arn:aws:ec2:us-east-1:123456789012:security-group/sg-xxxxxxxxxxxx',
  'awsRegion': 'us-east-1',
  'availabilityZone': 'Not Applicable',
  'configurationStateMd5Hash': '',
  'resourceCreationTime': None},
 'notificationCreationTime': '2021-06-29T10:53:45.937Z',
 'messageType': 'ConfigurationItemChangeNotification',
 'recordVersion': '1.3'}


evaluator_event = {
    'version': '1.0',
    'invokingEvent': json.dumps(invoking_event),
    'ruleParameters': '{"ThemisEvaluatorModule":"bad_ingress"}',
    'resultToken': 'result_token',
    'eventLeftScope': False,
    'executionRoleArn': 'arn:aws:iam::123456789012:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig',
    'configRuleArn': 'arn:aws:config:us-east-1:123456789012:config-rule/config-rule-itz6u5',
    'configRuleName': 'Themis-BadIngressRule-1VR2U2ASKBQW',
    'configRuleId': 'config-rule-itz6u5',
    'accountId': '123456789012'
}

class TestBadIngressEvaluator(unittest.TestCase):

    def test_should_not_be_applicable_for_resources_other_than_security_group(self):
        ev_event_cp = copy.deepcopy(evaluator_event)
        invoking_event_cp = copy.deepcopy(invoking_event)
        invoking_event_cp['configurationItem']['resourceType'] = 'AWS::EC2::VPC'
        ev_event_cp['invokingEvent'] = json.dumps(invoking_event_cp)
        ev = BadIngressEvaluator(ev_event_cp, None, True)
        self.assertEqual(ev.applicable(), False)

    def test_should_be_applicable_for_security_group_resource_type(self):
        ev = BadIngressEvaluator(evaluator_event, None, True)
        self.assertEqual(ev.applicable(), True)

    def test_should_not_be_applicable_for_delete_event(self):
        invoking_event_cp = copy.deepcopy(invoking_event)
        invoking_event_cp['configurationItemDiff']['changeType'] = 'DELETE'
        ev_event_cp = copy.deepcopy(evaluator_event)
        ev_event_cp['invokingEvent'] = json.dumps(invoking_event_cp)
        ev = BadIngressEvaluator(ev_event_cp, None, True)
        self.assertEqual(ev.applicable(), False)

    def test_should_be_applicable_on_first_run(self):
        invoking_event_cp = copy.deepcopy(invoking_event)
        invoking_event_cp['configurationItemDiff'] = None
        ev_event_cp = copy.deepcopy(evaluator_event)
        ev_event_cp['invokingEvent'] = json.dumps(invoking_event_cp)
        ev = BadIngressEvaluator(ev_event_cp, None, True)
        self.assertEqual(ev.applicable(), True)

    def test_should_not_be_applicable_when_sg_relationship_changes(self):
        """
        when sg is attached or detached, we get a config event. We should not evaluate
        rule for relation changes. Instead we should only evaluate when sg ip permission
        changes.
        """
        invoking_event_cp = copy.deepcopy(invoking_event)
        del invoking_event_cp['configurationItemDiff']['changedProperties']['Configuration.IpPermissions.1']
        del invoking_event_cp['configurationItemDiff']['changedProperties']['Configuration.IpPermissions.0']
        invoking_event_cp['configurationItemDiff']['changedProperties']['Relationships.0'] = {
            'previousValue': None,
            'updatedValue': {'resourceId': 'i-xxxxxxxxxxxx',
            'resourceName': None,
            'resourceType': 'AWS::EC2::Instance',
            'name': 'Is associated with Instance'},
            'changeType': 'CREATE'
        }
        ev_event_cp = copy.deepcopy(evaluator_event)
        ev_event_cp['invokingEvent'] = json.dumps(invoking_event_cp)
        ev = BadIngressEvaluator(ev_event_cp, None, True)
        self.assertEqual(ev.applicable(), False)

    def test_should_be_applicable_when_sg_ip_permission_changes(self):
        ev = BadIngressEvaluator(evaluator_event, None, True)
        self.assertEqual(ev.applicable(), True)


fixer_event = {
    "ResourceID": "sg-xxxxxxxxx"
}

sg_all_port_permission = json.loads("""
                    {
                        "IpProtocol": "-1",
                        "Ipv6Ranges": [],
                        "PrefixListIds": [],
                        "UserIdGroupPairs": [
                            {
                                "GroupId": "sg-0ji123kbk1248",
                                "UserId": "123456789012"
                            }
                        ],
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                    }
""")

sg_allowed_port = json.loads("""
                    {
                        "FromPort": 443,
                        "IpProtocol": "tcp",
                        "Ipv6Ranges": [],
                        "{refixListIds": [],
                        "ToPort": 443,
                        "UserIdGroupPairs": [],
                        "IpRanges": [
                            {
                                "CidrIp": "1.2.3.4/32",
                                "Description": "Allow https access"
                            }
                        ]
                    }
""")

class TestBadIngressFixer(unittest.TestCase):
    def test_modify_invalid_ingress_should_close_public_port_to_vpc_cidr(self):
        bi = BadIngressFixer(fixer_event, None, True)
        bi.vpc_cidr = "1.1.1.1/1"
        expected_modified_permissions = copy.deepcopy(sg_all_port_permission)
        expected_modified_permissions["IpRanges"][0]["CidrIp"] = "1.1.1.1/1"
        expected_modified_permissions["IpRanges"][0]["Description"] = "modified by themis rule : bad_ingress"
        modified = bi.modify_invalid_ingress([sg_all_port_permission])
        print(modified)
        self.assertEqual(modified, [expected_modified_permissions])

    def test_modify_invalid_ingress_should_not_close_allowed_port_to_vpc_cidr(self):
        bi = BadIngressFixer(fixer_event, None, True)
        bi.vpc_cidr = "1.1.1.1/1"
        modified = bi.modify_invalid_ingress([sg_allowed_port])
        self.assertEqual(modified, [sg_allowed_port])