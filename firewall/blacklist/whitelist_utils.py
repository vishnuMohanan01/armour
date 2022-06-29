def is_port_white_listed(port_no):
    """
    Checks if the port is whitelisted
    :param int port_no: port number to check
    :return: boolean, based on whether the port is whitelisted
    """

    if port_no == 22 or 60000 <= port_no <= 63000:
        return True
    return False
