# Aegis Shield Installation Guide for CachyOS

This guide provides detailed instructions for installing Aegis Shield on CachyOS systems, optimized for the CachyOS kernel and environment.

## System Requirements

- **CPU**: 4+ cores recommended (8+ for high-traffic networks)
- **RAM**: 8GB minimum (16GB+ recommended)
- **Storage**: 100GB+ free space for logs and packet captures
- **Network**: At least one network interface
- **OS**: CachyOS (latest version recommended)
- **Kernel**: CachyOS kernel (optimized for performance)
- **Privileges**: Root access required

## CachyOS-Specific Optimizations

Aegis Shield takes advantage of several CachyOS-specific optimizations:

- **CachyOS Kernel**: Optimized for performance with custom schedulers
- **BORE/SCHED_EXT Scheduler**: Better resource allocation for packet processing
- **Enhanced Memory Management**: Improved memory allocation for high-throughput packet analysis
- **Optimized Compiler Flags**: CachyOS packages are compiled with performance optimizations
- **Chaotic AUR Integration**: Easy access to required packages

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
   - For CachyOS, your network interface is likely `enp3s0` (as detected in your system)
   - The installer will handle all dependencies and configurations

### Method 2: Manual Installation

If you prefer to install manually or the automated installer fails, follow these steps:

1. **Install dependencies**:
   ```bash
   # Update system
   sudo pacman -Syu
   
   # Install base dependencies
   sudo pacman -S --needed base-devel git nodejs npm python python-pip curl wget libpcap nftables
   
   # CachyOS already has Chaotic AUR configured, but if not:
   if ! grep -q "chaotic-aur" /etc/pacman.conf; then
     sudo pacman-key --recv-key 3056513887B78AEB --keyserver keyserver.ubuntu.com
     sudo pacman-key --lsign-key 3056513887B78AEB
     sudo pacman -U --noconfirm 'https://cdn-mirror.chaotic.cx/chaotic-aur/chaotic-keyring.pkg.tar.zst' 'https://cdn-mirror.chaotic.cx/chaotic-aur/chaotic-mirrorlist.pkg.tar.zst'
     echo "[chaotic-aur]" | sudo tee -a /etc/pacman.conf
     echo "Include = /etc/pacman.d/chaotic-mirrorlist" | sudo tee -a /etc/pacman.conf
     sudo pacman -Sy
   fi
   
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
       monitoring: ["enp3s0"]  # Your CachyOS network interface
       management: "enp3s0"    # Your CachyOS network interface
   ```

8. **Enable and start services**:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable nftables
   sudo systemctl start nftables
   sudo systemctl enable aegis-shield
   sudo systemctl start aegis-shield
   ```

## CachyOS Performance Tuning

To maximize Aegis Shield performance on CachyOS:

### Kernel Parameter Optimization

Edit `/etc/sysctl.d/99-aegis-shield.conf`:

```bash
sudo nano /etc/sysctl.d/99-aegis-shield.conf
```

Add the following parameters:

```
# Network performance tuning
net.core.netdev_max_backlog = 250000
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 1024 65535
net.core.somaxconn = 65535

# Memory management for packet processing
vm.swappiness = 10
vm.dirty_ratio = 60
vm.dirty_background_ratio = 2
```

Apply the changes:

```bash
sudo sysctl -p /etc/sysctl.d/99-aegis-shield.conf
```

### CPU Scheduler Optimization

CachyOS already uses optimized schedulers (BORE/SCHED_EXT), but you can further tune for network processing:

```bash
# For BORE scheduler
echo "network" | sudo tee /sys/kernel/debug/sched/bore/task_classification
```

### Memory Allocation

For systems with 16GB+ RAM, allocate more memory to packet buffers:

```bash
sudo sed -i 's/pcap_buffer_size: 2048/pcap_buffer_size: 4096/' /etc/aegis-shield/config/config.yaml
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

## Troubleshooting CachyOS-Specific Issues

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

### Performance Issues

1. Check CPU scheduler:
   ```bash
   cat /sys/kernel/debug/sched/bore/version
   ```

2. Verify memory allocation:
   ```bash
   grep -i pcap_buffer /etc/aegis-shield/config/config.yaml
   ```

3. Check network interface settings:
   ```bash
   ethtool enp3s0 | grep -i "speed\|duplex\|link"
   ```

4. Verify kernel parameters:
   ```bash
   sysctl net.core.netdev_max_backlog
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

# Remove kernel parameter file
sudo rm /etc/sysctl.d/99-aegis-shield.conf
```

## Support

For support, please open an issue on GitHub or contact the maintainer directly.
