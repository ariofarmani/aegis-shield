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

## System Requirements

- **CPU**: 4+ cores recommended (8+ for high-traffic networks)
- **RAM**: 8GB minimum (16GB+ recommended)
- **Storage**: 100GB+ free space for logs and packet captures
- **Network**: 1Gbps+ network interface(s)
- **OS**: CachyOS or other Arch-based Linux distribution
- **Kernel**: Linux kernel 5.10+ (CachyOS kernel recommended)

## Installation

### Quick Install (CachyOS)

1. Clone this repository:
   ```bash
   git clone https://github.com/ariofarmani/aegis-shield.git
   cd aegis-shield
   ```

2. Run the installer as root:
   ```bash
   sudo ./install.sh
   ```

3. Follow the on-screen prompts to complete the installation.

4. Access the dashboard at http://localhost:8443

### Detailed Installation Guides

- [Arch Linux Installation Guide](docs/INSTALL-ARCH.md)
- [CachyOS Installation Guide](docs/INSTALL-CACHYOS.md)

## Configuration

The main configuration file is located at `/etc/aegis-shield/config/config.yaml`. This file contains all settings for the IDS/IPS system, including:

- Network interface configuration
- Detection engine settings
- Alerting and notification options
- Dashboard configuration
- Firewall integration settings

## Firewall Integration

Aegis Shield integrates with nftables to provide automatic blocking of malicious traffic. The firewall configuration is located at `/etc/aegis-shield/firewall/`.

To manage blocked IPs:

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

## Management Commands

```bash
# Check service status
sudo systemctl status aegis-shield

# Restart the service
sudo systemctl restart aegis-shield

# View logs
sudo journalctl -u aegis-shield -f

# View firewall rules
sudo nft list ruleset
```

## Security Considerations

- Aegis Shield requires root privileges to capture and analyze network traffic
- The dashboard is accessible only from localhost by default
- All sensitive files are protected with appropriate permissions
- Regular updates are recommended to maintain security

## License

Proprietary - All rights reserved

## Support

For support, please open an issue on GitHub or contact the maintainer directly.
