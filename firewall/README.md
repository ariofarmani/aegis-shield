# Aegis Shield Firewall Configuration

This directory contains firewall configuration files for Aegis Shield IDS/IPS using nftables.

## About nftables

nftables is the modern replacement for iptables in Linux, offering significant improvements:

- **Improved Performance**: More efficient packet processing architecture
- **Simpler Syntax**: More readable and maintainable rules
- **Better Atomic Rule Updates**: All rule changes applied at once or not at all
- **Enhanced Matching Capabilities**: More flexible packet matching options
- **Set Support**: Efficiently handle large IP blocklists

## Files

- `nftables-config.sh`: Script to configure nftables firewall rules
- `firewall-integration.js`: Node.js module for integrating with nftables
- `firewall-blocklist.txt`: List of IP addresses and ranges to block

## Usage

### nftables Configuration

To configure the firewall using nftables:

```bash
sudo ./nftables-config.sh
```

This will:
1. Install the necessary nftables configuration
2. Configure sets for IP and network blocking
3. Set up rate limiting for sensitive services
4. Create a helper script for dynamic IP blocking

### Manual IP Blocking

After running the configuration script, you can use the helper script to manually block IPs:

```bash
# To block an IP
sudo aegis-shield-block block 192.168.1.100

# To block an IP with a timeout (in seconds)
sudo aegis-shield-block block 192.168.1.100 3600

# To unblock an IP
sudo aegis-shield-block unblock 192.168.1.100
```

### Custom Blocklist

To add custom IP addresses to the blocklist:

1. Edit `firewall-blocklist.txt` to add your entries
2. Apply the changes with:
   ```bash
   sudo nft add element inet aegis-shield blocked_nets { 192.168.1.0/24 }
   ```

## Integration with Aegis Shield

Aegis Shield automatically integrates with nftables when:

- `integration.firewall.enabled` is set to `true` in `config.yaml`
- `integration.firewall.type` is set to `nftables`

The firewall integration handles:
- Automatically blocking malicious IPs detected by the IDS/IPS engines
- Managing block durations and expirations
- Persistent storage of blocked IPs
- Synchronizing the blocklist across restarts

## Advanced Configuration

### Viewing Current Rules

```bash
sudo nft list ruleset
```

### Working with Sets

View blocked IPs in the IPv4 set:
```bash
sudo nft list set inet aegis-shield blocked_ips
```

View blocked networks:
```bash
sudo nft list set inet aegis-shield blocked_nets
```

### Flushing Rules

If you need to clear all rules:
```bash
sudo nft flush ruleset
```

## Important Notes

- Always backup your existing firewall configuration before applying these rules
- These configurations assume a standard server setup and may need customization
- Some cloud environments may have additional firewall requirements
- The configuration automatically allows SSH (port 22) and the Aegis Shield dashboard (port 8443) 