import importlib
import json


def class_name(snake_case):
    e = ""
    for k in snake_case.split("_"):
        e += k.capitalize()
    return e


def get_module_from_event(event, key):
    mod = None
    # lambda invoked by config
    if event.get("ruleParameters"):
        rule_parameters = json.loads(event["ruleParameters"])
        if rule_parameters.get(key):
            mod = rule_parameters[key]
    # lambda invoked by ssm
    if event.get(key):
        mod = event[key]
    return mod


def execute(module_name, class_name, event, context, test_mode):
    module = importlib.import_module(f"{module_name}.{module_name}")
    class_to_handle = getattr(module, class_name)
    new_obj = class_to_handle(event, context, test_mode)
    if getattr(new_obj, "applicable")():
        return getattr(new_obj, "handle")()


def evaluate(event, context, test_mode):
    evaluator_module = get_module_from_event(event, "ThemisEvaluatorModule")
    print(f"evaluator_module: {evaluator_module}")
    if evaluator_module is not None:
        evaluator_class_name = class_name(evaluator_module + "_evaluator")
        return execute(evaluator_module, evaluator_class_name, event, context, test_mode)


def fix(event, context, test_mode):
    fixer_module = get_module_from_event(event, "ThemisFixerModule")
    print(f"fixer_module: {fixer_module}")
    if fixer_module is not None:
        fixer_class_name = class_name(fixer_module + "_fixer")
        return execute(fixer_module, fixer_class_name, event, context, test_mode)


def handle(event, context, test_mode=False):
    print(event)
    print(context)
    print(f"test_mode: {test_mode}")
    evaluate(event, context, test_mode)
    fix(event, context, test_mode)
