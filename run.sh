#!/bin/bash

echo "===================================="
echo "Network Device Scanner Installer"
echo "===================================="
echo ""
echo "Installing dependencies..."
pip3 install -r requirements.txt

if [ $? -ne 0 ]; then
    echo "ERROR: Failed to install dependencies. Please make sure pip is installed."
    exit 1
fi

echo ""
echo "Installing done! Running scanner..."
echo ""
python3 network_scanner.py

echo ""
echo "Press Enter to exit..."
read
