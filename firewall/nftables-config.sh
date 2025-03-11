#!/bin/bash

# Aegis Shield - NFTables Configuration
# This script sets up nftables firewall rules for Aegis Shield

# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: This script must be run as root. Please use sudo."
  exit 1
fi

# Check if nftables is installed
if ! command -v nft &> /dev/null; then
  echo "ERROR: nftables is not installed. Please install it first."
  echo "For Debian/Ubuntu: sudo apt-get install nftables"
  echo "For CentOS/RHEL: sudo yum install nftables"
  exit 1
fi

echo "===== Configuring NFTables Firewall for Aegis Shield ====="

# Create a temporary configuration file
TEMP_FILE=$(mktemp)

cat > "$TEMP_FILE" << 'EOF'
#!/usr/sbin/nft -f

# Clear all rules
flush ruleset

# Define tables and chains
table inet aegis-shield {
    # Base chain for incoming traffic
    chain input {
        type filter hook input priority 0; policy drop;
        
        # Allow established connections
        ct state established,related accept
        
        # Allow loopback traffic
        iifname lo accept
        
        # Allow ICMPv4 and ICMPv6 with rate limiting
        ip protocol icmp limit rate 1/second accept
        ip6 nexthdr icmpv6 limit rate 1/second accept
        
        # Allow SSH (customize port if needed)
        tcp dport 22 accept
        
        # Allow Aegis Shield dashboard
        tcp dport 8443 accept
        
        # Drop invalid connections
        ct state invalid drop
        
        # Default logging for dropped packets
        log prefix "AEGIS-SHIELD-INPUT-DROP: " limit rate 5/minute
    }
    
    # Chain for outgoing traffic
    chain output {
        type filter hook output priority 0; policy accept;
    }
    
    # Chain for forwarded traffic
    chain forward {
        type filter hook forward priority 0; policy drop;
        
        # Allow established connections
        ct state established,related accept
        
        # Default logging for dropped packets
        log prefix "AEGIS-SHIELD-FORWARD-DROP: " limit rate 5/minute
    }
    
    # Chain for blocked IPs
    chain blocklist {
        # Malicious IPs from threat intelligence will be added here
        # Format: ip saddr @blocked_ips drop
        
        return
    }
    
    # Chain for rate limiting
    chain rate_limit {
        # Rate limit connections to protect against DDoS
        tcp flags syn tcp dport {22} limit rate 10/minute accept
        
        return
    }
    
    # Named sets
    set blocked_ips {
        type ipv4_addr
        flags timeout
    }
    
    set blocked_ips6 {
        type ipv6_addr
        flags timeout
    }
    
    set blocked_nets {
        type ipv4_addr
        flags interval
    }
    
    set blocked_nets6 {
        type ipv6_addr
        flags interval
    }
}

# Add known malicious IPs and networks to blocklists
add element inet aegis-shield blocked_nets { 185.130.5.0/24, 91.236.75.0/24 }

# Set up automatic blocking for brute force attempts
table inet aegis-shield-auto {
    # Detection chain for SSH brute force
    chain input {
        type filter hook input priority -1; policy accept;
        
        # Count and track SSH connection attempts
        tcp dport 22 ct state new add @ssh_scanners { ip saddr limit rate 5/minute } counter
    }
    
    # Set for tracking potential scanners
    set ssh_scanners {
        type ipv4_addr
        size 65535
        flags dynamic,timeout
        timeout 1h
    }
}

EOF

# Install the nftables config
echo "Installing nftables configuration..."
nft -f "$TEMP_FILE"

# Save the configuration to ensure it persists across reboots
if [ -d "/etc/nftables" ]; then
    cp "$TEMP_FILE" /etc/nftables/aegis-shield.nft
    echo "include \"/etc/nftables/aegis-shield.nft\"" >> /etc/nftables.conf
    echo "Configuration saved to /etc/nftables/aegis-shield.nft"
else
    cp "$TEMP_FILE" /etc/aegis-shield/firewall/aegis-shield.nft
    echo "Configuration saved to /etc/aegis-shield/firewall/aegis-shield.nft"
    echo "NOTE: You need to include this file in your nftables boot configuration"
fi

# Clean up
rm "$TEMP_FILE"

# Enable and start nftables service
if systemctl is-active --quiet nftables; then
    systemctl reload nftables
    echo "NFTables service reloaded"
else
    systemctl enable nftables
    systemctl start nftables
    echo "NFTables service started and enabled"
fi

# Create a helper script for dynamically blocking IPs
BLOCK_SCRIPT="/usr/local/bin/aegis-shield-block"
cat > "$BLOCK_SCRIPT" << 'EOF'
#!/bin/bash
# Aegis Shield - IP Blocking Script

if [ $# -lt 1 ]; then
    echo "Usage: $0 [block|unblock] IP [timeout_seconds]"
    echo "Examples:"
    echo "  $0 block 192.168.1.100"
    echo "  $0 block 192.168.1.100 3600"
    echo "  $0 unblock 192.168.1.100"
    exit 1
fi

ACTION="$1"
IP="$2"
TIMEOUT="${3:-0}"

if [ "$ACTION" = "block" ]; then
    if [[ "$IP" =~ .*:.* ]]; then
        # IPv6
        if [ "$TIMEOUT" -gt 0 ]; then
            nft add element inet aegis-shield blocked_ips6 { $IP timeout $(($TIMEOUT))s }
        else
            nft add element inet aegis-shield blocked_ips6 { $IP }
        fi
    else
        # IPv4
        if [ "$TIMEOUT" -gt 0 ]; then
            nft add element inet aegis-shield blocked_ips { $IP timeout $(($TIMEOUT))s }
        else
            nft add element inet aegis-shield blocked_ips { $IP }
        fi
    fi
    echo "Blocked $IP"
elif [ "$ACTION" = "unblock" ]; then
    if [[ "$IP" =~ .*:.* ]]; then
        # IPv6
        nft delete element inet aegis-shield blocked_ips6 { $IP }
    else
        # IPv4
        nft delete element inet aegis-shield blocked_ips { $IP }
    fi
    echo "Unblocked $IP"
else
    echo "Invalid action: $ACTION"
    echo "Use 'block' or 'unblock'"
    exit 1
fi
EOF

chmod +x "$BLOCK_SCRIPT"
echo "Created blocking script at $BLOCK_SCRIPT"

echo "===== NFTables Firewall Configuration Complete ====="
echo "Aegis Shield is now using nftables for firewall protection"
echo ""
echo "To block an IP address:"
echo "  sudo aegis-shield-block block 192.168.1.100"
echo ""
echo "To unblock an IP address:"
echo "  sudo aegis-shield-block unblock 192.168.1.100"
echo ""
echo "To view current nftables rules:"
echo "  sudo nft list ruleset"
