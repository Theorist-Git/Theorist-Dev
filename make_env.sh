#!/usr/bin/sh

set -xe

sudo /opt/lampp/lampp stop
sudo systemctl start mysql
sudo systemctl start redis-server
python3 main.py