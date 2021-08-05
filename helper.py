import json
import boto3
from string import Template
from botocore.exceptions import ClientError
import settings
import os


def get_rules(module):
    themis_root_dir = os.path.dirname(__file__)
    rules_dir = os.path.join(themis_root_dir, "rules")
    default_rule_dir = os.path.join(rules_dir, "default")
    account_rule_dir = os.path.join(rules_dir, str(account_id()))
    rule_file = None
    if os.path.exists(account_rule_dir):
        rule_file = os.path.join(account_rule_dir, f"{module}.json")
    rule_file = os.path.join(default_rule_dir, f"{module}.json")
    print(f"{module} rule file: {rule_file}")
    rules = read_json(rule_file)
    print(rules)
    return rules


def read_json(file_location: str):
    with open(file_location, 'r') as f:
        data = json.load(f)
    return data


def get_from_dict(dict, *args):
    for key in args:
        value = dict.get(key)
        if value is not None:
            return value
    return None


def account_alias():
    client = boto3.client('iam')
    response = client.list_account_aliases()
    if response.get("AccountAliases"):
        if len(response['AccountAliases']) > 0:
            return response['AccountAliases'][0]
    return None


def account_id():
    client = boto3.client("sts")
    account_id = client.get_caller_identity().get('Account')
    return account_id


def convert_dict_to_html_table(py_dict, compliant):
    bg_color = "tomato"
    if compliant:
        bg_color = "lightgreen"
    elif compliant is None:
        bg_color = "grey"

    t = Template("""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                table {
                    width:100%;
                }
                table, th, td {
                    border: 1px solid black;
                    border-collapse: collapse;
                }
                th, td {
                    padding: 5px;
                    text-align: left;
                }
            </style>
        </head>
        <body>
            <table>
                $rows
            </table>
        </body>
        </html>
    """)
    table_rows = []
    for key in sorted(py_dict.keys()):
        table_rows.append(f"<tr><td style=\"background-color:{bg_color};\">{key}</td><td>{py_dict[key]}</td></tr>")
    s = t.substitute({
        "rows": "\n".join(table_rows),
        "bg_color": bg_color
    })
    return s


def send_email(subject, msg):
    client = boto3.client('ses')
    try:
        response = client.send_email(
            Source=settings.ses_sender_email(),
            Destination={
                'ToAddresses': settings.ses_reciever_emails(),
            },
            Message={
                'Body': {
                    'Html': {
                        'Charset': 'UTF-8',
                        'Data': msg,
                    },
                },
                'Subject': {
                    'Charset': 'UTF-8',
                    'Data': subject,
                },
            },
        )
    # Display an error if something goes wrong.
    except ClientError as e:
        print(e.response['Error']['Message'])
    else:
        print("Email sent! Message ID:"),
        print(response['ResponseMetadata']['RequestId'])
