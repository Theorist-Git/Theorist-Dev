#!/usr/bin/sh

set -xe

sudo /opt/lampp/lampp stop
sudo systemctl start mysql
python3 main.py