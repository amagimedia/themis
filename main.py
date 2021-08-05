from handler import handle
import os
import helper

if __name__ == "__main__":
    current_dir = os.path.dirname(__file__)
    event = helper.read_json("/Users/roshan/Downloads/sample_events/bad_ingres/config_event.json")
    handle(event, None, True)