"""
Child playbook that takes in a tenant ID and outputs to a Card of the event the Tenant Name. 
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'filter_1' block
    filter_1(container=container)

    return

@phantom.playbook_block()
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_1() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["playbook_input:tenant_id", "!=", ""]
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        list_lookup_value_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def pin_12(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("pin_12() called")

    format_1 = phantom.get_format_data(name="format_1")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(container=container, data=format_1, message="Crowdstrike Tenant", pin_style="blue", pin_type="card")

    return


@phantom.playbook_block()
def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_3() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["list_lookup_value_1:custom_function_result.success", "==", True]
        ],
        case_sensitive=False)

    # call connected blocks if condition 1 matched
    if found_match_1:
        format_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    pin_14(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def pin_14(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("pin_14() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(container=container, data="Not Found", message="Crowdstrike Tenant", pin_style="red", pin_type="card")

    return


@phantom.playbook_block()
def list_lookup_value_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("list_lookup_value_1() called")

    filtered_input_0_tenant_id = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:playbook_input:tenant_id"])

    parameters = []

    # build parameters list for 'list_lookup_value_1' call
    for filtered_input_0_tenant_id_item in filtered_input_0_tenant_id:
        parameters.append({
            "column_1": filtered_input_0_tenant_id_item[0],
            "custom_list": "Crowdstrike Tenant ID mappings",
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="local/list_lookup_value", parameters=parameters, name="list_lookup_value_1", callback=list_lookup_value_1_callback)

    return


@phantom.playbook_block()
def list_lookup_value_1_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("list_lookup_value_1_callback() called")

    
    decision_3(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    filter_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


@phantom.playbook_block()
def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_1() called")

    template = """{0}\n"""

    # parameter list for template variable replacement
    parameters = [
        "list_lookup_value_1:custom_function_result.data.column_2"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

    pin_12(container=container)

    return


@phantom.playbook_block()
def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_2() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["list_lookup_value_1:custom_function_result.data.column_2", "!=", ""]
        ],
        name="filter_2:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        pass

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    filtered_cf_result_0 = phantom.collect2(container=container, datapath=["filtered-data:filter_2:condition_1:list_lookup_value_1:custom_function_result.data.column_2"])

    filtered_cf_result_0_data_column_2 = [item[0] for item in filtered_cf_result_0]

    tenant_name_combined_value = phantom.concatenate(filtered_cf_result_0_data_column_2, dedup=True)

    output = {
        "tenant_name": tenant_name_combined_value,
    }

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

    phantom.save_playbook_output_data(output=output)

    return