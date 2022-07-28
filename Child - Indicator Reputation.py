"""
Child playbook to perform reputation on indicators.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'filter_1' block
    filter_1(container=container)

    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_1() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_input:file_hash", "!=", ""]
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        file_reputation_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


def file_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("file_reputation_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_input_0_file_hash = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:playbook_input:file_hash"])

    parameters = []

    # build parameters list for 'file_reputation_1' call
    for filtered_input_0_file_hash_item in filtered_input_0_file_hash:
        if filtered_input_0_file_hash_item[0] is not None:
            parameters.append({
                "hash": filtered_input_0_file_hash_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("file reputation", parameters=parameters, name="file_reputation_1", assets=["virustotal"], callback=file_reputation_1_callback)

    return


def file_reputation_1_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("file_reputation_1_callback() called")

    
    format_file_rep_note(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    decision_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


def add_note_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_note_1() called")

    format_file_rep_note = phantom.get_format_data(name="format_file_rep_note")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=format_file_rep_note, note_format="markdown", note_type="general", title="")

    return


def format_file_rep_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_file_rep_note() called")

    template = """%%\n## File Reputation\n**File Hash:** {0}\n\n**VirusTotal:** {1}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "file_reputation_1:action_result.parameter.hash",
        "file_reputation_1:action_result.message"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_file_rep_note")

    add_note_1(container=container)

    return


def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["file_reputation_1:action_result.summary.malicious", ">", 0]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        format_file_card(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    found_match_2 = phantom.decision(
        container=container,
        logical_operator="and",
        conditions=[
            ["file_reputation_1:action_result.summary.suspicious", ">", 0],
            ["file_reputation_1:action_result.summary.malicious", "==", 0]
        ])

    # call connected blocks if condition 2 matched
    if found_match_2:
        format_suspicious_file_card(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


def pin_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("pin_2() called")

    format_file_card = phantom.get_format_data(name="format_file_card")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(container=container, data=format_file_card, message="Malicious File Hash", pin_style="red", pin_type="card")

    return


def format_file_card(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_file_card() called")

    template = """%%\n{0}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "file_reputation_1:action_result.parameter.hash"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_file_card")

    pin_2(container=container)

    return


def format_suspicious_file_card(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_suspicious_file_card() called")

    template = """%%\n{0}\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "file_reputation_1:action_result.parameter.hash"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_suspicious_file_card")

    pin_4(container=container)

    return


def pin_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("pin_4() called")

    format_suspicious_file_card = phantom.get_format_data(name="format_suspicious_file_card")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(container=container, data=format_suspicious_file_card, message="Suspicious File", pin_style="grey", pin_type="card")

    return


def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    ################################################################################
    ## Custom Code End
    ################################################################################

    return