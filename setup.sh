#! /bin/bash

echo "initialing setup..."
sudo apt update -y && sudo apt upgrade -y
sleep 2m
sudo apt install tshark -y
python3 -m pip install pyshark

## check if user already a member of wireshark group


