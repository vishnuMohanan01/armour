import os
import sqlite3
import sys

# sys.argv[1] is project name
DB_ROOT = f"/var/local/{sys.argv[1]}"
DB_NAME = "armour.db"

# creating db directory if not exists
if not os.path.exists(DB_ROOT):
    os.makedirs(DB_ROOT)

# creating db file path
DB_PATH = os.path.join(DB_ROOT, DB_NAME)

con = sqlite3.connect(DB_PATH)

# create blacklist
con.execute("CREATE TABLE blacklist (address text NOT NULL);")

# create whitelist
con.execute("CREATE TABLE whitelist (address text NOT NULL);")

con.close()
