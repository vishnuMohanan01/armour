#! /bin/bash
set -xe

PROJECT_ROOT="/root/armour"
PROJECT_NAME="armour"
DB_ROOT="/var/local/${PROJECT_NAME}"

echo "initialing setup..."
sudo apt update -y && sudo apt upgrade -y
sleep 2m

mkdir -p $PROJECT_ROOT
git clone https://github.com/Iam-VM/armour.git $PROJECT_ROOT
cd $PROJECT_ROOT || exit

mkvirtualenv $PROJECT_NAME
echo "cd $PROJECT_ROOT" >> "/root/.virtualenvs/${PROJECT_NAME}/bin/postactivate"
workon $PROJECT_NAME

pip install -r requirements.txt

# install and config sqlite
apt install sqlite3 -y
mkdir -p $DB_ROOT
`which python` migrations/armour.sqlite.py $PROJECT_NAME && echo "Migrations Complete."


# persist iptables
apt-get install -y debconf-utils
echo "iptables-persistent iptables-persistent/autosave_v6 boolean false" | debconf-set-selections -v
echo "iptables-persistent iptables-persistent/autosave_v4 boolean false" | debconf-set-selections -v
sudo apt-get -y install iptables-persistent


# installing ipset
apt install ipset -y
IPSET_NAME="armour-blacklist"
ipset create $IPSET_NAME hash:ip
sudo iptables -I INPUT -m set --match-set $IPSET_NAME src -j DROP
# To remove the above rule: sudo iptables -D INPUT -m set --match-set $IPSET_NAME src -j DROP
# making ipset persistent
touch /etc/ipsets.conf
mv confs/ipset-persistent.service /etc/systemd/system/ipset-persistent.service
sudo systemctl daemon-reload
sudo systemctl start ipset-persistent
sudo systemctl enable ipset-persistent

# to add ip to set: ipset add armour-blacklist 206.189.130.141
# delete entry: ipset del armour-blacklist 206.189.130.141
