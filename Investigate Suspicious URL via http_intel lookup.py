"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'playbook_lookup_url_in_es_http_intel_collection_1' block
    playbook_lookup_url_in_es_http_intel_collection_1(container=container)

    return

@phantom.playbook_block()
def playbook_lookup_url_in_es_http_intel_collection_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook_lookup_url_in_es_http_intel_collection_1() called")

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.requestURL"])

    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]

    inputs = {
        "url": container_artifact_cef_item_0,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "conf25/Lookup url in ES http_intel collection", returns the playbook_run_id
    playbook_run_id = phantom.playbook("conf25/Lookup url in ES http_intel collection", container=container, name="playbook_lookup_url_in_es_http_intel_collection_1", callback=debug_1, inputs=inputs)

    return


@phantom.playbook_block()
def debug_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("debug_1() called")

    playbook_lookup_url_in_es_http_intel_collection_1_output_threat_key = phantom.collect2(container=container, datapath=["playbook_lookup_url_in_es_http_intel_collection_1:playbook_output:threat_key"])

    playbook_lookup_url_in_es_http_intel_collection_1_output_threat_key_values = [item[0] for item in playbook_lookup_url_in_es_http_intel_collection_1_output_threat_key]

    parameters = []

    parameters.append({
        "input_1": playbook_lookup_url_in_es_http_intel_collection_1_output_threat_key_values,
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

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return