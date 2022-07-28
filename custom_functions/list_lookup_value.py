def list_lookup_value(custom_list=None, column_1=None, **kwargs):
    """
    Looks up the first column in a custom list and returns the value in the second column on a matching row.
    
    Args:
        custom_list: Custom List
        column_1: Column 1 value to lookup
    
    Returns a JSON-serializable object that implements the configured data paths:
        column_2: Returned lookup value.
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    # Write your custom code here...
    if not custom_list:
        raise ValueError('custom_list parameter is required')
        
    if not column_1:
        raise ValueError('column_1 parameter is required')
    
    custom_list_request = phantom.requests.get(
        phantom.build_phantom_rest_url('decided_list', custom_list),
        verify=False
    )
    
    custom_list_request.raise_for_status()
    
    custom_list = custom_list_request.json().get('content', [])
    
    # phantom.debug('{}'.format(custom_list))
    
    for l in custom_list:
        it = iter(l)
        row_dict = dict(zip(it, it))
        try:
            row_dict[column_1]
        except KeyError:
            pass
        else:
            outputs = { 'column_2': row_dict[column_1] }
            
        
    # phantom.debug(json.dumps(outputs))
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
