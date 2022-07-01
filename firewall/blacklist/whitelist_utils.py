import os
import sqlite3

DB_ROOT = "/var/local/armour"
DB_NAME = "armour.db"

DB_PATH = os.path.join(DB_ROOT, DB_NAME)


def is_port_white_listed(port_no):
    """
    Checks if the port is whitelisted
    :param int port_no: port number to check
    :return: boolean, based on whether the port is whitelisted
    """

    if port_no == 22 or 60000 <= port_no <= 63000:
        return True
    return False


def is_ip_whitelisted(ip_address):
    con = sqlite3.connect(DB_PATH)

    cur = con.cursor()

    cur.execute("SELECT address from whitelist;")

    rows = cur.fetchall()
    ip = []
    for row in rows:
        ip.append(row[0])

    con.close()

    if ip_address in ip:
        return True

    return False
