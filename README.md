# Aegis Shield - Military-Grade IDS/IPS

![Aegis Shield](https://img.shields.io/badge/Status-Alpha-red)
![License](https://img.shields.io/badge/License-Proprietary-blue)
![Security](https://img.shields.io/badge/Security-Maximum-green)

Aegis Shield is a comprehensive, military-grade Intrusion Detection and Prevention System (IDS/IPS) designed to provide NSA-level security for critical infrastructure and sensitive networks. It integrates multiple detection engines, advanced behavioral analysis, and active threat intelligence to defend against sophisticated cyber threats.

## Key Features

- **Multi-Engine Architecture**: Integrates Suricata, Snort, and Zeek for comprehensive threat detection
- **Military-Grade Protection**: Designed to meet the highest security standards
- **Deep Packet Inspection**: Analyzes all network traffic for malicious patterns and behaviors
- **Behavioral Analysis**: Identifies unusual patterns that may indicate zero-day attacks
- **Intelligent Blocking**: Automatically blocks malicious IPs and attack patterns
- **Geographic Filtering**: Blocks traffic from high-risk countries
- **Advanced APT Detection**: Identifies and blocks Advanced Persistent Threats
- **SSL/TLS Inspection**: Analyzes encrypted traffic for hidden threats
- **Real-time Monitoring**: Provides immediate alerts and visualization of security events
- **Comprehensive Logging**: Maintains detailed audit trails for compliance and forensics
- **Zero Trust Security Model**: Verifies all traffic regardless of source
- **Custom Detection Rules**: Support for Suricata and Snort rule formats

## System Requirements

- Linux distribution (CentOS 7+, Ubuntu 18.04+, or Debian 10+)
- 8+ CPU cores recommended (4 minimum)
- 16+ GB RAM recommended (8GB minimum)
- 100+ GB storage space
- Two network interfaces (monitoring and management)
- Root privileges for installation and execution

## Dependencies

- Node.js 16+
- Suricata 6+
- Snort 3+
- Zeek 4+
- Libpcap
- Express.js
- Winston
- js-yaml
- pcap (Node.js pcap library)
- node-schedule
- geoip-lite
- ip-range-check

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/aegis-shield.git
cd aegis-shield
```

### 2. Install System Dependencies

For Debian/Ubuntu-based systems:

```bash
sudo apt update
sudo apt install -y nodejs npm libpcap-dev suricata snort zeek
```

For CentOS/RHEL-based systems:

```bash
sudo yum install -y epel-release
sudo yum install -y nodejs npm libpcap-devel suricata snort zeek
```

### 3. Install Node.js Dependencies

```bash
npm install
```

### 4. Configure Aegis Shield

Edit the configuration file to match your network setup:

```bash
sudo mkdir -p /etc/aegis-shield
sudo cp config/aegis-shield-config.yaml /etc/aegis-shield/config.yaml
sudo nano /etc/aegis-shield/config.yaml
```

Set the monitoring interface, protection level, and other parameters according to your requirements.

### 5. Install Rules

```bash
sudo mkdir -p /etc/aegis-shield/rules/suricata
sudo mkdir -p /etc/aegis-shield/rules/snort
sudo cp rules/aegis-shield-suricata-rules.rules /etc/aegis-shield/rules/suricata/
sudo cp rules/aegis-shield-snort-rules.rules /etc/aegis-shield/rules/snort/
```

### 6. Create Data and Log Directories

```bash
sudo mkdir -p /var/log/aegis-shield
sudo mkdir -p /var/lib/aegis-shield
sudo mkdir -p /var/run/aegis-shield
```

### 7. Install as a Service

```bash
sudo cp service/aegis-shield.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable aegis-shield
```

### 8. Start Aegis Shield

```bash
sudo systemctl start aegis-shield
```

## Usage

### Checking Status

```bash
sudo systemctl status aegis-shield
```

### Accessing the Dashboard

The web dashboard is available at:

```
https://[your-server-ip]:8443
```

Use the credentials you set in the configuration file to log in.

### Viewing Logs

```bash
sudo journalctl -u aegis-shield -f
```

### Managing Blocked IPs

Block an IP address:

```bash
curl -X POST -H "Content-Type: application/json" \
  -d '{"ip":"192.168.1.100", "reason":"Suspicious activity"}' \
  http://localhost:8443/api/block
```

Unblock an IP address:

```bash
curl -X POST -H "Content-Type: application/json" \
  -d '{"ip":"192.168.1.100"}' \
  http://localhost:8443/api/unblock
```

View the blocklist:

```bash
curl http://localhost:8443/api/blocklist
```

## Architecture

Aegis Shield employs a layered defense approach:

1. **Traffic Capture Layer**: Monitors all network traffic using libpcap
2. **Protocol Analysis Layer**: Dissects and analyzes packets at all OSI layers
3. **Detection Engine Layer**: Processes packets through multiple detection engines
4. **Correlation Layer**: Combines alerts from different engines for context-aware detection
5. **Response Layer**: Takes action based on detected threats
6. **Reporting Layer**: Provides visibility into security events

## Firewall Integration

Aegis Shield seamlessly integrates with system firewalls to provide active threat blocking capabilities:

- **Automated Blocking**: Instantly blocks malicious IPs detected by the system
- **Multiple Firewall Support**: Works with both iptables and UFW
- **Preconfigured Rules**: Includes optimized firewall configurations
- **Known Threat Blocklist**: Preloaded with known malicious IP addresses and ranges
- **Dynamic Rule Updates**: Continuously updates firewall rules based on threat intelligence

The firewall integration module provides:
- Configurable blocking duration
- Geolocation-based filtering
- Rate limiting for connection attempts
- Protection against common attack vectors

To configure the firewall integration:
1. Enable firewall integration in the configuration file
2. Choose your preferred firewall type (iptables or UFW)
3. Run the appropriate firewall configuration script from the `firewall` directory

## Custom Rules

Aegis Shield supports both Suricata and Snort rule formats. To add custom rules:

1. Create your rule files in Suricata or Snort format
2. Place them in the appropriate rules directory:
   - Suricata: `/etc/aegis-shield/rules/suricata/`
   - Snort: `/etc/aegis-shield/rules/snort/`
3. Restart the service to apply the new rules

## Security Considerations

Aegis Shield is designed to be deployed in a secure environment:

- Use strong authentication for the management interface
- Isolate the monitoring interface from administrative access
- Use TLS for all management communications
- Regularly update rules and threat intelligence
- Monitor system logs for signs of tampering

## Documentation

Full documentation is available in the `docs` directory:

- [Installation Guide](docs/installation.md)
- [Configuration Reference](docs/configuration.md)
- [API Documentation](docs/api.md)
- [Rule Writing Guide](docs/rules.md)
- [Troubleshooting](docs/troubleshooting.md)

## License

This software is proprietary and may only be used according to the terms of your license agreement.

## Disclaimer

Aegis Shield is designed for defensive security purposes only. The creators are not responsible for any misuse of this software. Always ensure you have proper authorization before deploying on any network.

## Firewall Integration Update

### NFTables Integration

Aegis Shield now uses NFTables as the primary firewall backend, replacing the legacy iptables implementation. NFTables provides several advantages:

- **Improved Performance**: Better packet processing architecture
- **Enhanced Ruleset Management**: More efficient rule organization and evaluation
- **IPv4/IPv6 Unified Handling**: Unified handling of both IPv4 and IPv6
- **Advanced Matching Capabilities**: More flexible packet matching
- **Better Scalability**: Handles large rulesets more efficiently

### Key Features of the NFTables Integration

- **Automatic Table Setup**: Creates necessary tables and chains for Aegis Shield operation
- **Dynamic IP Blocking**: Efficiently blocks malicious IPs with optional expiration times
- **Network Range Blocking**: Blocks entire networks using CIDR notation
- **Auto-Detection**: Detects and blocks brute force and DDoS attempts automatically
- **Stateful Packet Inspection**: Maintains connection state for better filtering
- **Performance Optimizations**: Rules are optimized for minimal impact on system performance

### Usage

The integration includes a command-line utility for managing blocked IPs:

```bash
# Block an IP address
sudo aegis-shield-block block 192.168.1.100

# Block an IP temporarily (e.g., for 1 hour)
sudo aegis-shield-block block 192.168.1.100 3600

# Unblock an IP address
sudo aegis-shield-block unblock 192.168.1.100

# Block a network range
sudo aegis-shield-block block-net 192.168.1.0/24

# List all blocked IPs and networks
sudo aegis-shield-block list

# Show firewall status
sudo aegis-shield-block status

# Export blocklist to a file
sudo aegis-shield-block export blocklist.txt

# Import blocklist from a file
sudo aegis-shield-block import blocklist.txt
```

### Bug Fixes

This update includes several bug fixes:

- Fixed race condition in the IP blocking mechanism
- Improved error handling for network operations
- Better validation of IP addresses and CIDR ranges
- Fixed issue with IPv6 address handling
- Optimized batch operations for better performance
- Added proper logging for all firewall operations

### Configuration

The firewall configuration can be customized in the main Aegis Shield configuration file:

```yaml
integration:
  firewall:
    enabled: true
    type: nftables
    auto_block: true
    block_duration: 86400  # 24 hours in seconds
    log_dropped: true
```

## About Aegis Shield

Aegis Shield provides enterprise-grade security through a multi-layered approach:

- **Signature-Based Detection**: Utilizing Suricata and Snort rules
- **Anomaly Detection**: Identifying unusual network patterns
- **Behavioral Analysis**: Monitoring system activity for suspicious behavior
- **Active Response**: Automatically blocking threats in real-time
- **Comprehensive Logging**: Detailed logs for forensic analysis

### Installation

For full installation instructions, see the [Installation Guide](docs/installation.md). 