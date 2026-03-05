#!/bin/bash

# Define colors for terminal output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}=========================================================${NC}"
echo -e "${GREEN}🛠️  IoT-Shield: Automated Environment Setup${NC}"
echo -e "${GREEN}=========================================================${NC}\n"

# 1. System Updates and Core Dependencies
echo -e "${BLUE}[INFO] Updating package lists and installing core system dependencies...${NC}"
sudo apt update
# Added build-essential to ensure GCC is available for compiling the C benchmark
sudo apt install -y python3-venv python3-pip apparmor-utils build-essential

# 2. Automated Tshark Installation & Permission Configuration
echo -e "\n${BLUE}[INFO] Installing tshark and configuring security policies...${NC}"

# This magic line automatically answers "Yes" to the Wireshark interactive prompt
echo "wireshark-common wireshark-common/install-setuid boolean true" | sudo debconf-set-selections
sudo apt install -y tshark
sudo dpkg-reconfigure -f noninteractive wireshark-common

# Add the current user to the wireshark group
sudo usermod -aG wireshark $USER
echo -e "${YELLOW}[SUCCESS] User '$USER' added to the 'wireshark' group.${NC}"

# Disable AppArmor profile for tshark to prevent silent permission blocks on local files
echo -e "${BLUE}[INFO] Adjusting AppArmor profiles for unhindered PCAP reading...${NC}"
if command -v aa-disable &> /dev/null; then
    sudo aa-disable /usr/bin/tshark 2>/dev/null || true
    sudo aa-disable /usr/bin/dumpcap 2>/dev/null || true
fi

# 3. Python Virtual Environment (Isolation)
echo -e "\n${BLUE}[INFO] Setting up Python Virtual Environment (.venv)...${NC}"
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
    echo -e "${YELLOW}[SUCCESS] Virtual environment created.${NC}"
else
    echo -e "${YELLOW}[INFO] Virtual environment already exists. Skipping creation.${NC}"
fi

# Activate venv
source .venv/bin/activate

# 4. Install Machine Learning, Data Science & Networking Packages
echo -e "\n${BLUE}[INFO] Installing Python dependencies via pip...${NC}"
pip install --upgrade pip

# Core ML and Data processing
pip install pandas numpy scikit-learn joblib

# Academic visualization
pip install matplotlib seaborn

# High-performance packet parsing and system monitoring
pip install dpkt psutil

# C-code transpilation for TinyML Edge deployment
pip install m2cgen

# 5. Fix Dataset Permissions (If the folder exists)
if [ -d "Pcaps" ]; then
    echo -e "\n${BLUE}[INFO] Normalizing file ownership and permissions for the 'Pcaps' directory...${NC}"
    sudo chown -R $USER:$USER Pcaps/
    sudo chmod -R +r Pcaps/
    sudo chmod -R +X Pcaps/
fi

echo -e "\n${GREEN}=========================================================${NC}"
echo -e "${GREEN}✅ Setup Completed Successfully!${NC}"
echo -e "${YELLOW}⚠️  IMPORTANT: You must apply the new group permissions by running:${NC}"
echo -e "${BLUE}    source .venv/bin/activate && newgrp wireshark${NC}"
echo -e "${GREEN}=========================================================${NC}"