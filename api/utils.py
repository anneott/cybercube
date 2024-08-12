def convert_list_to_json(rows, colnames):
    """
    When querying data from database then it runs data as list of lists. Convert it to json format to output from API.
    Datetime object need to be handled separately. Return a pydantic object
    :param rows:
    :type rows:
    :param colnames:
    :type colnames:
    :return:
    :rtype:
    """
    result = [dict(zip(colnames, row)) for row in rows]
    return result

