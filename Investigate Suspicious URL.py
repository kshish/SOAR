"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'playbook_retrieve_collection_data_1' block
    playbook_retrieve_collection_data_1(container=container)

    return

@phantom.playbook_block()
def playbook_retrieve_collection_data_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook_retrieve_collection_data_1() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.requestURL"])

    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]

    inputs = {
        "collection_name": ["http_intel"],
        "field_name": ["url"],
        "value": container_artifact_cef_item_0,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "conf25/retrieve collection data", returns the playbook_run_id
    playbook_run_id = phantom.playbook("conf25/retrieve collection data", container=container, name="playbook_retrieve_collection_data_1", callback=decision_1, inputs=inputs)

    return


@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["playbook_retrieve_collection_data_1:playbook_output:threat_key", "==", ""]
        ],
        conditions_dps=[
            ["playbook_retrieve_collection_data_1:playbook_output:threat_key", "==", ""]
        ],
        name="decision_1:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        return

    # check for 'else' condition 2
    container_update_1(action=action, success=success, container=container, results=results, handle=handle)
    prompt_1(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def container_update_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("container_update_1() called")

    parameters = []

    parameters.append({
        "container_input": None,
        "name": None,
        "description": None,
        "label": None,
        "owner": None,
        "sensitivity": None,
        "severity": "high",
        "status": "open",
        "tags": None,
        "input_json": None,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/container_update", parameters=parameters, name="container_update_1", callback=format_1)

    return


@phantom.playbook_block()
def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_1() called")

    template = """Caution!!!\n\nThreat key match: {0}\n"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_retrieve_collection_data_1:playbook_output:threat_key"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

    add_comment_3(container=container)

    return


@phantom.playbook_block()
def add_comment_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_comment_3() called")

    format_1 = phantom.get_format_data(name="format_1")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=format_1)

    return


@phantom.playbook_block()
def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("prompt_1() called")

    # set approver and message variables for phantom.prompt call

    user = "soar_local_admin"
    role = None
    message = """Threat key not found in threat list!\n\nThreat list: {0}\nThreat key: {1}\n\n\n"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_retrieve_collection_data_1:playbook_input:collection_name",
        "playbook_retrieve_collection_data_1:playbook_input:value"
    ]

    # responses
    response_types = [
        {
            "prompt": "Would you like to add threat key to threat list",
            "options": {
                "type": "list",
                "required": True,
                "choices": [
                    "Yes",
                    "No"
                ],
            },
        }
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=30, name="prompt_1", parameters=parameters, response_types=response_types, callback=decision_2)

    return


@phantom.playbook_block()
def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_2() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["prompt_1:action_result.summary.responses.0", "==", "Yes"]
        ],
        conditions_dps=[
            ["prompt_1:action_result.summary.responses.0", "==", "Yes"]
        ],
        name="decision_2:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        format_2(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    format_3(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def format_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_2() called")

    template = """Caution!! Threat key added to threat list by SOC analyst.\n\nThreat list: {0}\nThreat key: {1}\n"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_retrieve_collection_data_1:playbook_input:collection_name",
        "playbook_retrieve_collection_data_1:playbook_input:value"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_2")

    playbook_create_record_for_http_intel_collection_1(container=container)

    return


@phantom.playbook_block()
def playbook_create_record_for_http_intel_collection_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook_create_record_for_http_intel_collection_1() called")

    playbook_retrieve_collection_data_1_input_value = phantom.collect2(container=container, datapath=["playbook_retrieve_collection_data_1:playbook_input:value"])
    prompt_1_result_data = phantom.collect2(container=container, datapath=["prompt_1:action_result.summary.answered_at"], action_results=results)

    playbook_retrieve_collection_data_1_input_value_values = [item[0] for item in playbook_retrieve_collection_data_1_input_value]
    prompt_1_summary_answered_at = [item[0] for item in prompt_1_result_data]

    inputs = {
        "url": playbook_retrieve_collection_data_1_input_value_values,
        "threat_key": ["Manually Added"],
        "time": prompt_1_summary_answered_at,
        "_user": ["nobody"],
        "_key": [],
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "conf25/Create record for http_intel collection", returns the playbook_run_id
    playbook_run_id = phantom.playbook("conf25/Create record for http_intel collection", container=container, inputs=inputs)

    return


@phantom.playbook_block()
def format_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_3() called")

    template = """Threat key lookup tested negative\n\n{0}\n"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_retrieve_collection_data_1:playbook_input:value"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_3")

    add_comment_4(container=container)

    return


@phantom.playbook_block()
def add_comment_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_comment_4() called")

    format_3 = phantom.get_format_data(name="format_3")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=format_3)

    set_status_set_severity_5(container=container)

    return


@phantom.playbook_block()
def set_status_set_severity_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("set_status_set_severity_5() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_status(container=container, status="closed")
    phantom.set_severity(container=container, severity="low")

    container = phantom.get_container(container.get('id', None))

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return