"""
Child playbook for hunting in Crowdstrike.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'filter_1' block
    filter_1(container=container)
    # call 'event_filter' block
    event_filter(container=container)

    return

@phantom.playbook_block()
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_1() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        logical_operator="and",
        conditions=[
            ["playbook_input:file_hash", "!=", ""],
            ["playbook_input:tenant_name", "!=", ""]
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        sensor_filter(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        hunt_file_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        get_indicator_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def hunt_file_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("hunt_file_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_input_0_file_hash = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:playbook_input:file_hash"])

    parameters = []

    # build parameters list for 'hunt_file_1' call
    for filtered_input_0_file_hash_item in filtered_input_0_file_hash:
        if filtered_input_0_file_hash_item[0] is not None:
            parameters.append({
                "hash": filtered_input_0_file_hash_item[0],
                "limit": 100,
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################
    phantom.debug('########## CUSTOM CODE #############')
    asset_name = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:playbook_input:tenant_name"])
    phantom.debug('asset_name: {}'.format(asset_name[0]))
    phantom.debug('########## END CUSTOM CODE #############')

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("hunt file", parameters=parameters, name="hunt_file_1", assets=asset_name[0], callback=get_system_info_1)

    return

@phantom.playbook_block()
def list_processes_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("list_processes_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_input_0_sensor_id = phantom.collect2(container=container, datapath=["filtered-data:sensor_filter:condition_1:playbook_input:sensor_id"])
    filtered_input_1_file_hash = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:playbook_input:file_hash"])

    parameters = []

    # build parameters list for 'list_processes_1' call
    for filtered_input_0_sensor_id_item in filtered_input_0_sensor_id:
        for filtered_input_1_file_hash_item in filtered_input_1_file_hash:
            if filtered_input_0_sensor_id_item[0] is not None and filtered_input_1_file_hash_item[0] is not None:
                parameters.append({
                    "id": filtered_input_0_sensor_id_item[0],
                    "ioc": filtered_input_1_file_hash_item[0],
                    "limit": 100,
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    phantom.debug('########## CUSTOM CODE #############')
    asset_name = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:playbook_input:tenant_name"])
    phantom.debug('asset_name: {}'.format(asset_name[0]))
    phantom.debug('########## END CUSTOM CODE #############')

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("list processes", parameters=parameters, name="list_processes_1", assets=asset_name[0], callback=get_process_detail_1)

    return

@phantom.playbook_block()
def get_system_info_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_system_info_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    hunt_file_1_result_data = phantom.collect2(container=container, datapath=["hunt_file_1:action_result.data.*.device_id","hunt_file_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'get_system_info_1' call
    for hunt_file_1_result_item in hunt_file_1_result_data:
        if hunt_file_1_result_item[0] is not None:
            parameters.append({
                "id": hunt_file_1_result_item[0],
                "context": {'artifact_id': hunt_file_1_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    phantom.debug('########## CUSTOM CODE #############')
    asset_name = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:playbook_input:tenant_name"])
    phantom.debug('asset_name: {}'.format(asset_name[0]))
    phantom.debug('########## END CUSTOM CODE #############')

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get system info", parameters=parameters, name="get_system_info_1", assets=asset_name[0], callback=join_format_1)

    return

@phantom.playbook_block()
def get_process_detail_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_process_detail_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    list_processes_1_result_data = phantom.collect2(container=container, datapath=["list_processes_1:action_result.data.*.falcon_process_id","list_processes_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'get_process_detail_1' call
    for list_processes_1_result_item in list_processes_1_result_data:
        if list_processes_1_result_item[0] is not None:
            parameters.append({
                "falcon_process_id": list_processes_1_result_item[0],
                "context": {'artifact_id': list_processes_1_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    phantom.debug('########## CUSTOM CODE #############')
    asset_name = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:playbook_input:tenant_name"])
    phantom.debug('asset_name: {}'.format(asset_name[0]))
    phantom.debug('########## END CUSTOM CODE #############')

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get process detail", parameters=parameters, name="get_process_detail_1", assets=asset_name[0], callback=join_format_1)

    return

@phantom.playbook_block()
def join_format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_format_1() called")

    if phantom.completed(action_names=["get_system_info_1", "get_process_detail_1"]):
        # call connected block "format_1"
        format_1(container=container, handle=handle)

    return


@phantom.playbook_block()
def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_1() called")

    template = """CrowdStrike detected the following suspicious activity on an endpoint:\n\n| Field | Value |\n|---|---|\n| Host | {0} |\n| Command Line | {1} |\n| SHA 256 | {2} |\n| File Path | {3}\\\\{4}\n| CrowdStrike Detection Link | {5} |\n| Details of processes associated with the file hash | <see \"get process details\" action results> |\n| Count of machines that have the file on disk | {6} |\n| System information of machines that have the file on disk | <see \"get system info\" action results> |\n\n\n"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:event_filter:condition_1:artifact:*.cef.sourceHostName",
        "filtered-data:event_filter:condition_1:artifact:*.cef. cmdLine",
        "filtered-data:event_filter:condition_1:artifact:*.cef.fileHashSha256",
        "filtered-data:event_filter:condition_1:artifact:*.cef.filePath",
        "filtered-data:event_filter:condition_1:artifact:*.cef.fileName",
        "filtered-data:event_filter:condition_1:artifact:*.cef.falconHostLink",
        "hunt_file_1:action_result.summary.device_count"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

    pin_add_note_1(container=container)

    return


@phantom.playbook_block()
def event_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("event_filter() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.label", "==", "event"]
        ],
        name="event_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        join_format_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def pin_add_note_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("pin_add_note_1() called")

    format_1 = phantom.get_format_data(name="format_1")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(container=container, data="Crowdstrike Hunt", message="Completed hunting in Crowdstrike", pin_style="grey", pin_type="card")
    phantom.add_note(container=container, content=format_1, note_format="markdown", note_type="general", title="Crowdstrike Hunt Results")

    return


@phantom.playbook_block()
def sensor_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("sensor_filter() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_input:sensor_id", "!=", ""]
        ],
        name="sensor_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        list_processes_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def get_indicator_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_indicator_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_input_0_file_hash = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:playbook_input:file_hash"])

    parameters = []

    # build parameters list for 'get_indicator_1' call
    for filtered_input_0_file_hash_item in filtered_input_0_file_hash:
        parameters.append({
            "indicator_value": filtered_input_0_file_hash_item[0],
            "indicator_type": "sha256",
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get indicator", parameters=parameters, name="get_indicator_1", assets=["crowdstrike"], callback=decision_1)

    return


@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["get_indicator_1:action_result.message", "==", "Indicator not found"]
        ],
        case_sensitive=False)

    # call connected blocks if condition 1 matched
    if found_match_1:
        add_comment_pin_2(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    pin_3(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def add_comment_pin_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_comment_pin_2() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="Indicator not found")
    phantom.pin(container=container, data="No indicator found", message="Crowdstrike", pin_style="grey", pin_type="card")

    return


@phantom.playbook_block()
def pin_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("pin_3() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(container=container, data="Indicator found", message="Crowdstrike", pin_style="blue", pin_type="card")

    return


@phantom.playbook_block()
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