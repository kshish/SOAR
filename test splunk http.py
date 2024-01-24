"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'get_data_1' block
    get_data_1(container=container)

    return

@phantom.playbook_block()
def get_data_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_data_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    parameters = []

    parameters.append({
        "location": "/services/search/jobs",
        "headers": "Authorization: Bearer eyJraWQiOiJzcGx1bmsuc2VjcmV0IiwiYWxnIjoiSFM1MTIiLCJ2ZXIiOiJ2MiIsInR0eXAiOiJzdGF0aWMifQ.eyJpc3MiOiJhZG1pbiBmcm9tIGlwLTEwLTItNC0yNDUiLCJzdWIiOiJzb2FyX3NlcnZpY2VfYWNjb3VudCIsImF1ZCI6InN0dWRlbnRzIiwiaWRwIjoiU3BsdW5rIiwianRpIjoiMTMxYzMyMjAzN2E5ZmU0NjFiZTA1ZmJlYjdjYzUwOTFmNzQxZDRhOTE0MzdiMDZkNDA2MGE1ZjhhMTIyMjQ2OSIsImlhdCI6MTcwNjA1NTEwNCwiZXhwIjoxNzA4NjQ3MTA0LCJuYnIiOjE3MDYwNTUxMDR9.HbPW9SjE7ct29pEAOSn1m5ZGdsy7LOKL93-bB4qYiBWgxfmn19osMFuJCRaE7Y0n9bb5CaKsBppIQQ74ukfaPw",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get data", parameters=parameters, name="get_data_1", assets=["splunk"])

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