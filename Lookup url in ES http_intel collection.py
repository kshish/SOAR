"""
Lookup url in ES http_intel collection and return threat key
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'format_query' block
    format_query(container=container)

    return

@phantom.playbook_block()
def format_endpoint(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_endpoint() called")

    template = """storage/collections/data/http_intel?query=\n"""

    # parameter list for template variable replacement
    parameters = [
        "format_query:formatted_data"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_endpoint")

    get_data_1(container=container)
    debug_1(container=container)

    return


@phantom.playbook_block()
def get_data_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_data_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    format_endpoint = phantom.get_format_data(name="format_endpoint")

    parameters = []

    if format_endpoint is not None:
        parameters.append({
            "location": format_endpoint,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get data", parameters=parameters, name="get_data_1", assets=["splunk es"])

    return


@phantom.playbook_block()
def format_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_query() called")

    template = """{{\"url\":\"{0}\"}}\n"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:url"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_query")

    format_endpoint(container=container)

    return


@phantom.playbook_block()
def debug_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("debug_1() called")

    format_endpoint = phantom.get_format_data(name="format_endpoint")

    parameters = []

    parameters.append({
        "input_1": format_endpoint,
        "input_2": None,
        "input_3": None,
        "input_4": None,
        "input_5": None,
        "input_6": None,
        "input_7": None,
        "input_8": None,
        "input_9": None,
        "input_10": None,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/debug", parameters=parameters, name="debug_1")

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    get_data_1_result_data = phantom.collect2(container=container, datapath=["get_data_1:action_result.data.*.parsed_response_body.threat_key","get_data_1:action_result.data.*.parsed_response_body.record.*.threat_key"])

    get_data_1_result_item_0 = [item[0] for item in get_data_1_result_data]
    get_data_1_result_item_1 = [item[1] for item in get_data_1_result_data]

    threat_key_combined_value = phantom.concatenate(get_data_1_result_item_0, get_data_1_result_item_1)

    output = {
        "threat_key": threat_key_combined_value,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_playbook_output_data(output=output)

    return