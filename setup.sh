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
`which python` migrations/armour.sqlite.py $PROJECT_NAME && echo "Migrations Complete"

