import os
import sqlite3


DB_ROOT = "/var/local/armour"
DB_NAME = "armour.db"
IPSET_NAME = "armour-blacklist"

# creating db file path
DB_PATH = os.path.join(DB_ROOT, DB_NAME)


def add_ip_in_bl_table(ip_address):
    con = sqlite3.connect(DB_PATH)

    # add ip to blacklist
    con.execute(f"INSERT INTO blacklist (address) VALUES ('{ip_address}');")
    con.commit()
    con.close()


def add_address_to_ipset(ip_address):
    os.system(f"ipset add {IPSET_NAME} {ip_address}")


def remove_address_from_ipset(ip_address):
    os.system(f"ipset del {IPSET_NAME} {ip_address}")


def blacklist(ip_address):
    add_ip_in_bl_table(ip_address=ip_address)
    add_address_to_ipset(ip_address=ip_address)
