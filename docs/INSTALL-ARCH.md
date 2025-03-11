# Aegis Shield Installation Guide for Arch Linux

This guide provides detailed instructions for installing Aegis Shield on Arch Linux systems.

## System Requirements

- **CPU**: 4+ cores recommended (8+ for high-traffic networks)
- **RAM**: 8GB minimum (16GB+ recommended)
- **Storage**: 100GB+ free space for logs and packet captures
- **Network**: At least one network interface
- **OS**: Arch Linux or Arch-based distribution
- **Kernel**: Linux kernel 5.10+
- **Privileges**: Root access required

## Installation Methods

### Method 1: Using the Automated Installer (Recommended)

1. **Update your system**:
   ```bash
   sudo pacman -Syu
   ```

2. **Install Git**:
   ```bash
   sudo pacman -S --needed git
   ```

3. **Clone the repository**:
   ```bash
   git clone https://github.com/ariofarmani/aegis-shield.git
   cd aegis-shield
   ```

4. **Run the installer**:
   ```bash
   sudo ./install.sh
   ```

5. **Follow the prompts**:
   - The installer will check your system requirements
   - You'll be asked to specify your network interface(s)
   - The installer will handle all dependencies and configurations

### Method 2: Manual Installation

If you prefer to install manually or the automated installer fails, follow these steps:

1. **Install dependencies**:
   ```bash
   # Update system
   sudo pacman -Syu
   
   # Install base dependencies
   sudo pacman -S --needed base-devel git nodejs npm python python-pip curl wget libpcap nftables
   
   # Add Chaotic AUR repository (for easier access to some packages)
   sudo pacman-key --recv-key 3056513887B78AEB --keyserver keyserver.ubuntu.com
   sudo pacman-key --lsign-key 3056513887B78AEB
   sudo pacman -U --noconfirm 'https://cdn-mirror.chaotic.cx/chaotic-aur/chaotic-keyring.pkg.tar.zst' 'https://cdn-mirror.chaotic.cx/chaotic-aur/chaotic-mirrorlist.pkg.tar.zst'
   echo "[chaotic-aur]" | sudo tee -a /etc/pacman.conf
   echo "Include = /etc/pacman.d/chaotic-mirrorlist" | sudo tee -a /etc/pacman.conf
   sudo pacman -Sy
   
   # Install Suricata and Zeek
   sudo pacman -S --needed suricata zeek
   
   # Install Snort3 from AUR
   git clone https://aur.archlinux.org/snort3.git
   cd snort3
   makepkg -si
   cd ..
   
   # Install Node.js dependencies
   sudo npm install -g express winston js-yaml pcap node-schedule geoip-lite ip-range-check
   ```

2. **Create directories**:
   ```bash
   sudo mkdir -p /opt/aegis-shield/src/modules
   sudo mkdir -p /etc/aegis-shield/config
   sudo mkdir -p /etc/aegis-shield/rules/suricata
   sudo mkdir -p /etc/aegis-shield/rules/snort
   sudo mkdir -p /etc/aegis-shield/firewall
   sudo mkdir -p /var/log/aegis-shield
   sudo mkdir -p /var/lib/aegis-shield
   sudo mkdir -p /var/run/aegis-shield
   ```

3. **Clone the repository**:
   ```bash
   git clone https://github.com/ariofarmani/aegis-shield.git
   cd aegis-shield
   ```

4. **Copy files**:
   ```bash
   # Copy source files
   sudo cp -r src/* /opt/aegis-shield/src/
   sudo cp -r src/modules/* /opt/aegis-shield/src/modules/
   
   # Copy configuration files
   sudo cp -r config/* /etc/aegis-shield/config/
   
   # Copy firewall files
   sudo cp -r firewall/* /etc/aegis-shield/firewall/
   
   # Copy service files
   sudo cp -r service/* /etc/systemd/system/
   
   # Copy rule files
   sudo cp -r rules/suricata/* /etc/aegis-shield/rules/suricata/
   sudo cp -r rules/snort/* /etc/aegis-shield/rules/snort/
   
   # Copy package.json
   sudo cp package.json /opt/aegis-shield/
   ```

5. **Set permissions**:
   ```bash
   sudo chmod -R 750 /opt/aegis-shield
   sudo chmod -R 750 /etc/aegis-shield
   sudo chmod -R 750 /var/log/aegis-shield
   sudo chmod -R 750 /var/lib/aegis-shield
   sudo chmod -R 750 /var/run/aegis-shield
   
   # Make scripts executable
   sudo find /opt/aegis-shield -name "*.sh" -exec chmod +x {} \;
   sudo find /etc/aegis-shield -name "*.sh" -exec chmod +x {} \;
   sudo chmod +x /etc/aegis-shield/firewall/nftables-config-fixed.sh
   ```

6. **Configure firewall**:
   ```bash
   sudo bash /etc/aegis-shield/firewall/nftables-config-fixed.sh
   ```

7. **Update configuration**:
   Edit `/etc/aegis-shield/config/config.yaml` and update the network interface settings:
   
   ```yaml
   network:
     interfaces:
       monitoring: ["your_interface_name"]
       management: "your_interface_name"
   ```

   Replace `your_interface_name` with your actual network interface name (e.g., `eth0`, `enp3s0`).

8. **Enable and start services**:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable nftables
   sudo systemctl start nftables
   sudo systemctl enable aegis-shield
   sudo systemctl start aegis-shield
   ```

## Post-Installation

### Verify Installation

```bash
# Check service status
sudo systemctl status aegis-shield

# View logs
sudo journalctl -u aegis-shield -f

# Check firewall rules
sudo nft list ruleset
```

### Access the Dashboard

Open your browser and navigate to:
```
http://localhost:8443
```

### Managing Aegis Shield

```bash
# Start the service
sudo systemctl start aegis-shield

# Stop the service
sudo systemctl stop aegis-shield

# Restart the service
sudo systemctl restart aegis-shield

# View logs
sudo journalctl -u aegis-shield -f
```

### Managing Firewall Rules

```bash
# List all blocked IPs
sudo aegis-shield-block list

# Block an IP address
sudo aegis-shield-block block 192.168.1.100

# Block an IP with a timeout (in seconds)
sudo aegis-shield-block block 192.168.1.100 3600

# Unblock an IP address
sudo aegis-shield-block unblock 192.168.1.100
```

## Troubleshooting

### Service Fails to Start

1. Check the logs:
   ```bash
   sudo journalctl -u aegis-shield -e
   ```

2. Verify Node.js is installed correctly:
   ```bash
   node --version
   npm --version
   ```

3. Check if the main script exists:
   ```bash
   ls -la /opt/aegis-shield/src/index.js
   ```

### Firewall Issues

1. Check nftables status:
   ```bash
   sudo systemctl status nftables
   ```

2. View current ruleset:
   ```bash
   sudo nft list ruleset
   ```

3. Reset and reconfigure:
   ```bash
   sudo nft flush ruleset
   sudo bash /etc/aegis-shield/firewall/nftables-config-fixed.sh
   ```

### Dashboard Not Accessible

1. Check if the service is running:
   ```bash
   sudo systemctl status aegis-shield
   ```

2. Verify port is open:
   ```bash
   sudo ss -tuln | grep 8443
   ```

3. Check firewall rules:
   ```bash
   sudo nft list ruleset | grep 8443
   ```

## Uninstallation

If you need to uninstall Aegis Shield:

```bash
# Stop and disable services
sudo systemctl stop aegis-shield
sudo systemctl disable aegis-shield

# Remove files
sudo rm -rf /opt/aegis-shield
sudo rm -rf /etc/aegis-shield
sudo rm -rf /var/log/aegis-shield
sudo rm -rf /var/lib/aegis-shield
sudo rm -rf /var/run/aegis-shield

# Remove service file
sudo rm /etc/systemd/system/aegis-shield.service
sudo systemctl daemon-reload
```

## Support

For support, please open an issue on GitHub or contact the maintainer directly.
