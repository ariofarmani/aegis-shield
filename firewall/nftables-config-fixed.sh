#!/bin/bash

# Aegis Shield - NFTables Configuration (Enhanced Version)
# This script sets up nftables firewall rules for Aegis Shield with bug fixes and optimizations

# Set up error handling
set -e
trap 'echo "Error occurred at line $LINENO. Command: $BASH_COMMAND"' ERR

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print section headers
print_header() {
  echo -e "${BLUE}========================================================${NC}"
  echo -e "${BLUE}$1${NC}"
  echo -e "${BLUE}========================================================${NC}"
}

# Function to print success message
print_success() {
  echo -e "${GREEN}✓ $1${NC}"
}

# Function to print error message
print_error() {
  echo -e "${RED}✗ $1${NC}"
  return 1
}

# Function to print warning message
print_warning() {
  echo -e "${YELLOW}! $1${NC}"
}

# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
  print_error "ERROR: This script must be run as root. Please use sudo."
  exit 1
fi

# Check if nftables is installed
if ! command -v nft &> /dev/null; then
  print_error "ERROR: nftables is not installed. Please install it first."
  echo "For Debian/Ubuntu: sudo apt-get install nftables"
  echo "For CentOS/RHEL: sudo yum install nftables"
  echo "For Arch Linux: sudo pacman -S nftables"
  exit 1
fi

print_header "CONFIGURING NFTABLES FIREWALL FOR AEGIS SHIELD"

# Check if nftables service is running
if systemctl is-active --quiet nftables; then
  print_success "nftables service is running"
else
  print_warning "nftables service is not running. Starting it now..."
  systemctl start nftables
  if systemctl is-active --quiet nftables; then
    print_success "nftables service started successfully"
  else
    print_error "Failed to start nftables service. Please check the service status."
    exit 1
  fi
fi

# Backup existing ruleset
BACKUP_FILE="/tmp/nftables-backup-$(date +%Y%m%d%H%M%S).nft"
echo "Backing up current nftables ruleset to $BACKUP_FILE..."
nft list ruleset > "$BACKUP_FILE" 2>/dev/null || true
print_success "Ruleset backup created"

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
        
        # Allow essential services
        tcp dport { 80, 443 } accept comment "Allow HTTP/HTTPS"
        udp dport 53 accept comment "Allow DNS"
        
        # Apply blocklist for IPv4
        ip saddr @blocked_ips drop
        
        # Apply blocklist for IPv6
        ip6 saddr @blocked_ips6 drop
        
        # Apply network blocklist
        ip saddr @blocked_nets drop
        ip6 saddr @blocked_nets6 drop
        
        # Drop invalid connections
        ct state invalid drop
        
        # Default logging for dropped packets
        log prefix "AEGIS-SHIELD-INPUT-DROP: " flags all limit rate 5/minute
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
        log prefix "AEGIS-SHIELD-FORWARD-DROP: " flags all limit rate 5/minute
    }
    
    # Chain for connection rate limiting
    chain conn_limit {
        # Rate limit for new connections to protect against flooding
        tcp flags syn tcp dport != 22 limit rate 100/second burst 20 packets return
        
        # Excessive connection attempts get logged and dropped
        log prefix "AEGIS-SHIELD-CONN-FLOOD: " flags all limit rate 5/minute
        drop
    }
    
    # Named sets for IPv4
    set blocked_ips {
        type ipv4_addr
        flags timeout
        timeout 1d
    }
    
    # Named sets for IPv6
    set blocked_ips6 {
        type ipv6_addr
        flags timeout
        timeout 1d
    }
    
    # CIDR sets for network blocks
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
add element inet aegis-shield blocked_nets { 185.130.5.0/24, 91.236.75.0/24, 45.83.64.0/20 }

# Set up automatic abuse detection and blocking
table inet aegis-shield-auto {
    # Map to count SSH connection attempts
    map ssh_tracker {
        type ipv4_addr : counter
        size 65535
        flags dynamic,timeout
        timeout 1h
    }
    
    # Map to count HTTP flood attempts
    map http_tracker {
        type ipv4_addr : counter
        size 65535
        flags dynamic,timeout
        timeout 10m
    }
    
    # Set for tracking detected scanners (actively blocked)
    set ssh_scanners {
        type ipv4_addr
        size 65535
        flags dynamic,timeout
        timeout 1d
    }
    
    # Chain for detecting brute force and scanning
    chain input {
        type filter hook input priority -1; policy accept;
        
        # Count SSH connection attempts
        tcp dport 22 ct state new add @ssh_tracker { ip saddr : counter }
        
        # Count HTTP requests to detect DDoS
        tcp dport { 80, 8443 } ct state new add @http_tracker { ip saddr : counter }
        
        # Block SSH brute forcing
        ip saddr @ssh_scanners drop
        
        # Detect and block SSH scanners
        tcp dport 22 ct state new ip saddr map @ssh_tracker counter gt 10 \
            add @ssh_scanners { ip saddr } \
            log prefix "AEGIS-SHIELD-BRUTE-FORCE: " drop
        
        # Detect HTTP DDoS
        tcp dport { 80, 8443 } ct state new ip saddr map @http_tracker counter gt 200 \
            add @ssh_scanners { ip saddr } \
            log prefix "AEGIS-SHIELD-HTTP-FLOOD: " drop
    }
}

# Advanced intrusion prevention settings
table inet aegis-shield-ids {
    chain check_packets {
        type filter hook prerouting priority -450; policy accept;
        
        # Drop malformed packets
        tcp flags & (fin|syn|rst|psh|ack|urg) == 0 drop
        tcp flags & (fin|syn) == (fin|syn) drop
        tcp flags & (syn|rst) == (syn|rst) drop
        tcp flags & (fin|rst) == (fin|rst) drop
        tcp flags & (fin|ack) == fin drop
        tcp flags & (ack|urg) == urg drop
        
        # Drop Christmas tree packets
        tcp flags & (fin|syn|rst|psh|ack|urg) == (fin|syn|rst|psh|ack|urg) drop
        
        # Anti-spoofing measures
        ip saddr 127.0.0.0/8 iifname != "lo" drop
        ip saddr 0.0.0.0/8 drop
        ip saddr 240.0.0.0/4 drop
        ip saddr 169.254.0.0/16 drop
        ip saddr 192.0.2.0/24 drop
        ip saddr 204.152.64.0/23 drop
        ip saddr 224.0.0.0/3 drop
        
        # Drop fragments
        ip frag-off & 0x1fff != 0 drop
    }
}

# Optimization specific chains for higher performance
table inet aegis-shield-opt {
    chain optimize {
        type filter hook forward priority -150; policy accept;
        
        # Enable conntrack helpers based on protocol
        ct helper set "ftp" ip protocol tcp tcp dport 21
        ct helper set "tftp" ip protocol udp udp dport 69
        ct helper set "irc" ip protocol tcp tcp dport 6667
        
        # Perform early drop of obviously malicious traffic
        ip protocol tcp tcp flags syn tcp option maxseg size 1-536 drop
    }
}
EOF

# Install the nftables config
echo "Installing nftables configuration..."
if ! nft -f "$TEMP_FILE"; then
  print_error "Failed to apply nftables rules. Rolling back to previous configuration..."
  if [ -f "$BACKUP_FILE" ]; then
    nft -f "$BACKUP_FILE" || print_warning "Couldn't restore previous configuration"
  fi
  exit 1
fi

print_success "NFTables rules applied successfully"

# Save the configuration to ensure it persists across reboots
CONFIG_DIR="/etc/nftables"
if [ -d "$CONFIG_DIR" ]; then
    # For standard nftables installation
    cp "$TEMP_FILE" "$CONFIG_DIR/aegis-shield.nft"
    
    # Update main configuration to include our rules
    if [ -f "$CONFIG_DIR/nftables.conf" ]; then
        # Check if include line already exists
        if ! grep -q "aegis-shield.nft" "$CONFIG_DIR/nftables.conf"; then
            echo "include \"$CONFIG_DIR/aegis-shield.nft\"" >> "$CONFIG_DIR/nftables.conf"
        fi
    else
        # Create new configuration file
        echo "#!/usr/sbin/nft -f" > "$CONFIG_DIR/nftables.conf"
        echo "include \"$CONFIG_DIR/aegis-shield.nft\"" >> "$CONFIG_DIR/nftables.conf"
    fi
    
    print_success "Configuration saved to $CONFIG_DIR/aegis-shield.nft"
else
    # Create directory if it doesn't exist
    mkdir -p /etc/aegis-shield/firewall
    cp "$TEMP_FILE" /etc/aegis-shield/firewall/aegis-shield.nft
    print_success "Configuration saved to /etc/aegis-shield/firewall/aegis-shield.nft"
    
    # Create systemd service to load rules on boot
    cat > /etc/systemd/system/aegis-shield-firewall.service << EOF
[Unit]
Description=Aegis Shield Firewall Rules
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/nft -f /etc/aegis-shield/firewall/aegis-shield.nft
ExecStop=/usr/sbin/nft flush ruleset
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable aegis-shield-firewall.service
    print_success "Created systemd service for firewall rules"
fi

# Clean up
rm "$TEMP_FILE"

# Create and setup the advanced management script
BLOCK_SCRIPT="/usr/local/bin/aegis-shield-block"
cat > "$BLOCK_SCRIPT" << 'EOF'
#!/bin/bash
# Aegis Shield - Enhanced IP Management Script

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default timeout (0 = permanent)
DEFAULT_TIMEOUT=86400  # 1 day in seconds

# Function to display usage information
usage() {
  echo "Aegis Shield IP Management Tool"
  echo
  echo "Usage: $0 COMMAND [OPTIONS]"
  echo
  echo "Commands:"
  echo "  block IP [TIMEOUT]           Block an IP address"
  echo "  unblock IP                   Unblock an IP address"
  echo "  block-net NETWORK            Block a network range (CIDR notation)"
  echo "  unblock-net NETWORK          Unblock a network range"
  echo "  list                         List all blocked IPs and networks"
  echo "  status                       Show nftables status"
  echo "  export [FILE]                Export blocklist to a file"
  echo "  import FILE                  Import blocklist from a file"
  echo
  echo "Examples:"
  echo "  $0 block 192.168.1.100"
  echo "  $0 block 192.168.1.100 3600     (block for 1 hour)"
  echo "  $0 unblock 192.168.1.100"
  echo "  $0 block-net 192.168.1.0/24"
  echo "  $0 list"
  echo
  echo "Note: This tool requires root privileges."
  exit 1
}

# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
  echo -e "${RED}ERROR: This script must be run as root. Please use sudo.${NC}"
  exit 1
fi

# Check if nftables is installed
if ! command -v nft &> /dev/null; then
  echo -e "${RED}ERROR: nftables is not installed.${NC}"
  exit 1
fi

# Check if the Aegis Shield table exists
if ! nft list tables | grep -q "aegis-shield"; then
  echo -e "${RED}ERROR: Aegis Shield firewall is not properly configured.${NC}"
  echo "Please run the nftables configuration script first."
  exit 1
fi

# Function to validate IP address
validate_ip() {
  local ip=$1
  if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    # IPv4 validation
    IFS='.' read -r -a ip_parts <<< "$ip"
    for part in "${ip_parts[@]}"; do
      if [[ $part -gt 255 || $part -lt 0 ]]; then
        return 1
      fi
    done
    return 0
  elif [[ $ip =~ ^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$ ]]; then
    # Simple IPv6 validation (not comprehensive)
    return 0
  else
    return 1
  fi
}

# Function to validate CIDR notation
validate_cidr() {
  local cidr=$1
  
  # Extract IP part and prefix length
  if [[ $cidr =~ ^([0-9.]+)/([0-9]+)$ ]]; then
    local ip="${BASH_REMATCH[1]}"
    local prefix="${BASH_REMATCH[2]}"
    
    # Validate IP
    if ! validate_ip "$ip"; then
      return 1
    fi
    
    # Validate prefix length
    if [[ $prefix -lt 0 || $prefix -gt 32 ]]; then
      return 1
    fi
    
    return 0
  elif [[ $cidr =~ ^([0-9a-fA-F:]+)/([0-9]+)$ ]]; then
    local ip="${BASH_REMATCH[1]}"
    local prefix="${BASH_REMATCH[2]}"
    
    # Simple IPv6 CIDR validation
    if [[ $prefix -lt 0 || $prefix -gt 128 ]]; then
      return 1
    fi
    
    return 0
  else
    return 1
  fi
}

# Function to block an IP address
block_ip() {
  local ip=$1
  local timeout=$2
  
  # Validate IP address
  if ! validate_ip "$ip"; then
    echo -e "${RED}Invalid IP address: $ip${NC}"
    return 1
  fi
  
  # Check if IP is already blocked
  if nft list set inet aegis-shield blocked_ips | grep -q "$ip"; then
    echo -e "${YELLOW}IP address $ip is already blocked.${NC}"
    return 0
  fi
  
  # Determine if IPv4 or IPv6
  if [[ $ip =~ .*:.* ]]; then
    # IPv6
    if [ "$timeout" -gt 0 ]; then
      nft add element inet aegis-shield blocked_ips6 { $ip timeout $(($timeout))s }
    else
      nft add element inet aegis-shield blocked_ips6 { $ip }
    fi
  else
    # IPv4
    if [ "$timeout" -gt 0 ]; then
      nft add element inet aegis-shield blocked_ips { $ip timeout $(($timeout))s }
    else
      nft add element inet aegis-shield blocked_ips { $ip }
    fi
  fi
  
  if [ $? -eq 0 ]; then
    echo -e "${GREEN}Successfully blocked IP address: $ip${NC}"
    if [ "$timeout" -gt 0 ]; then
      echo -e "${BLUE}Block will expire after $timeout seconds.${NC}"
    else
      echo -e "${BLUE}Block is permanent.${NC}"
    fi
  else
    echo -e "${RED}Failed to block IP address: $ip${NC}"
    return 1
  fi
  
  return 0
}

# Function to unblock an IP address
unblock_ip() {
  local ip=$1
  
  # Validate IP address
  if ! validate_ip "$ip"; then
    echo -e "${RED}Invalid IP address: $ip${NC}"
    return 1
  fi
  
  # Determine if IPv4 or IPv6
  if [[ $ip =~ .*:.* ]]; then
    # IPv6
    nft delete element inet aegis-shield blocked_ips6 { $ip }
  else
    # IPv4
    nft delete element inet aegis-shield blocked_ips { $ip }
  fi
  
  if [ $? -eq 0 ]; then
    echo -e "${GREEN}Successfully unblocked IP address: $ip${NC}"
  else
    echo -e "${YELLOW}IP address $ip was not in the blocklist.${NC}"
  fi
  
  return 0
}

# Function to block a network range
block_network() {
  local network=$1
  
  # Validate CIDR notation
  if ! validate_cidr "$network"; then
    echo -e "${RED}Invalid network CIDR: $network${NC}"
    return 1
  fi
  
  # Determine if IPv4 or IPv6
  if [[ $network =~ .*:.* ]]; then
    # IPv6
    nft add element inet aegis-shield blocked_nets6 { $network }
  else
    # IPv4
    nft add element inet aegis-shield blocked_nets { $network }
  fi
  
  if [ $? -eq 0 ]; then
    echo -e "${GREEN}Successfully blocked network: $network${NC}"
  else
    echo -e "${RED}Failed to block network: $network${NC}"
    return 1
  fi
  
  return 0
}

# Function to unblock a network range
unblock_network() {
  local network=$1
  
  # Validate CIDR notation
  if ! validate_cidr "$network"; then
    echo -e "${RED}Invalid network CIDR: $network${NC}"
    return 1
  fi
  
  # Determine if IPv4 or IPv6
  if [[ $network =~ .*:.* ]]; then
    # IPv6
    nft delete element inet aegis-shield blocked_nets6 { $network }
  else
    # IPv4
    nft delete element inet aegis-shield blocked_nets { $network }
  fi
  
  if [ $? -eq 0 ]; then
    echo -e "${GREEN}Successfully unblocked network: $network${NC}"
  else
    echo -e "${YELLOW}Network $network was not in the blocklist.${NC}"
  fi
  
  return 0
}

# Function to list all blocked IPs and networks
list_blocks() {
  echo -e "${BLUE}===== Blocked IPv4 Addresses =====${NC}"
  nft list set inet aegis-shield blocked_ips
  
  echo -e "\n${BLUE}===== Blocked IPv6 Addresses =====${NC}"
  nft list set inet aegis-shield blocked_ips6
  
  echo -e "\n${BLUE}===== Blocked IPv4 Networks =====${NC}"
  nft list set inet aegis-shield blocked_nets
  
  echo -e "\n${BLUE}===== Blocked IPv6 Networks =====${NC}"
  nft list set inet aegis-shield blocked_nets6
  
  echo -e "\n${BLUE}===== Auto-blocked Scanners =====${NC}"
  nft list set inet aegis-shield-auto ssh_scanners
}

# Function to show nftables status
show_status() {
  echo -e "${BLUE}===== NFTables Status =====${NC}"
  
  if systemctl is-active --quiet nftables; then
    echo -e "${GREEN}NFTables service is running${NC}"
  else
    echo -e "${RED}NFTables service is not running${NC}"
  fi
  
  echo -e "\n${BLUE}===== Current Ruleset =====${NC}"
  nft list ruleset
}

# Function to export blocklist to a file
export_blocklist() {
  local file=$1
  
  if [ -z "$file" ]; then
    file="aegis-shield-blocklist-$(date +%Y%m%d).txt"
  fi
  
  echo "# Aegis Shield Blocklist" > "$file"
  echo "# Generated: $(date)" >> "$file"
  echo "# Format: TYPE|ADDRESS" >> "$file"
  echo "" >> "$file"
  
  # Export IPv4 addresses
  for ip in $(nft list set inet aegis-shield blocked_ips | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}'); do
    echo "ip|$ip" >> "$file"
  done
  
  # Export IPv4 networks
  for net in $(nft list set inet aegis-shield blocked_nets | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}'); do
    echo "net|$net" >> "$file"
  done
  
  # Export IPv6 addresses (simplified)
  for ip in $(nft list set inet aegis-shield blocked_ips6 | grep -oE '([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}'); do
    echo "ip6|$ip" >> "$file"
  done
  
  echo -e "${GREEN}Blocklist exported to $file${NC}"
}

# Function to import blocklist from a file
import_blocklist() {
  local file=$1
  
  if [ ! -f "$file" ]; then
    echo -e "${RED}File not found: $file${NC}"
    return 1
  fi
  
  local count=0
  
  while IFS="|" read -r type address || [[ -n "$type" ]]; do
    # Skip comments and empty lines
    [[ "$type" =~ ^#.*$ || -z "$type" ]] && continue
    
    case "$type" in
      ip)
        block_ip "$address" 0
        ((count++))
        ;;
      ip6)
        block_ip "$address" 0
        ((count++))
        ;;
      net)
        block_network "$address"
        ((count++))
        ;;
      *)
        echo -e "${YELLOW}Unknown entry type: $type${NC}"
        ;;
    esac
  done < "$file"
  
  echo -e "${GREEN}Imported $count entries from $file${NC}"
}

# Main function
main() {
  local command=$1
  shift
  
  case "$command" in
    block)
      local ip=$1
      local timeout=${2:-0}
      
      if [ -z "$ip" ]; then
        echo -e "${RED}Error: IP address is required${NC}"
        usage
      fi
      
      block_ip "$ip" "$timeout"
      ;;
    unblock)
      local ip=$1
      
      if [ -z "$ip" ]; then
        echo -e "${RED}Error: IP address is required${NC}"
        usage
      fi
      
      unblock_ip "$ip"
      ;;
    block-net)
      local network=$1
      
      if [ -z "$network" ]; then
        echo -e "${RED}Error: Network CIDR is required${NC}"
        usage
      fi
      
      block_network "$network"
      ;;
    unblock-net)
      local network=$1
      
      if [ -z "$network" ]; then
        echo -e "${RED}Error: Network CIDR is required${NC}"
        usage
      fi
      
      unblock_network "$network"
      ;;
    list)
      list_blocks
      ;;
    status)
      show_status
      ;;
    export)
      export_blocklist "$1"
      ;;
    import)
      local file=$1
      
      if [ -z "$file" ]; then
        echo -e "${RED}Error: File path is required${NC}"
        usage
      fi
      
      import_blocklist "$file"
      ;;
    *)
      echo -e "${RED}Unknown command: $command${NC}"
      usage
      ;;
  esac
}

# If no arguments, show usage
if [ $# -lt 1 ]; then
  usage
fi

# Call the main function with all arguments
main "$@"
EOF

chmod +x "$BLOCK_SCRIPT"
echo "Created enhanced blocking script at $BLOCK_SCRIPT"

# Enable and start nftables service if not already running
if ! systemctl is-enabled --quiet nftables; then
  systemctl enable nftables
  print_success "NFTables service enabled"
fi

if ! systemctl is-active --quiet nftables; then
  systemctl start nftables
  print_success "NFTables service started"
fi

# Test the configuration
echo "Testing nftables configuration..."
if nft list ruleset | grep -q "aegis-shield"; then
  print_success "NFTables configuration test successful"
else
  print_error "NFTables configuration test failed"
  exit 1
fi

print_header "NFTABLES FIREWALL CONFIGURATION COMPLETE"
echo ""
echo "Aegis Shield is now using nftables for firewall protection"
echo ""
echo "Usage examples:"
echo "  sudo aegis-shield-block block 192.168.1.100           # Block an IP permanently"
echo "  sudo aegis-shield-block block 192.168.1.100 3600      # Block an IP for 1 hour"
echo "  sudo aegis-shield-block unblock 192.168.1.100         # Unblock an IP"
echo "  sudo aegis-shield-block block-net 192.168.1.0/24      # Block a network range"
echo "  sudo aegis-shield-block list                          # List all blocked IPs"
echo "  sudo aegis-shield-block status                        # Show firewall status"
echo ""
echo "To view current nftables rules:"
echo "  sudo nft list ruleset" 