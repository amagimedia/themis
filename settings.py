import os
import json


def settings_json():
    json_path = os.path.join(os.path.dirname(__file__), "settings.json")
    with open(json_path, "r") as f:
        j = json.load(f)
    return j


def ses_sender_email():
    s = settings_json()
    return s["themis"]["notification_sender_email"]


def ses_reciever_emails():
    s = settings_json()
    return s["themis"]["notification_reciever_emails"]
