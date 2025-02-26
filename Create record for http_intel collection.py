"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'format_json_body' block
    format_json_body(container=container)

    return

@phantom.playbook_block()
def post_data_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("post_data_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    format_collection_update_endpoint = phantom.get_format_data(name="format_collection_update_endpoint")
    format_json_body = phantom.get_format_data(name="format_json_body")

    parameters = []

    if format_collection_update_endpoint is not None:
        parameters.append({
            "location": format_collection_update_endpoint,
            "body": format_json_body,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("post data", parameters=parameters, name="post_data_1", assets=["splunk da ess threat intel"])

    return


@phantom.playbook_block()
def format_json_body(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_json_body() called")

    template = """{{\"url\": \"{0}\", \"threat_key\": \"{1}\", \"time\": \"{2}\", \"_key\": \"{3}\", \"_user\": \"{4}\"}}\n"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:url",
        "playbook_input:threat_key",
        "playbook_input:time",
        "playbook_input:_key",
        "playbook_input:_user"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_json_body")

    format_collection_update_endpoint(container=container)

    return


@phantom.playbook_block()
def format_collection_update_endpoint(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_collection_update_endpoint() called")

    template = """servicesNS/nobody/DA-ESS-ThreatIntelligence/storage/collections/data/http_intel\n"""

    # parameter list for template variable replacement
    parameters = []

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_collection_update_endpoint")

    post_data_1(container=container)

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