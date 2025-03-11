/**
 * Aegis Shield - Firewall Integration Module
 * 
 * This module provides integration with the system firewall.
 * Updated version using nftables instead of iptables
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { promisify } = require('util');
const { exec, spawn } = require('child_process');
const execAsync = promisify(exec);

// Default paths
const BLOCKLIST_PATH = '/var/lib/aegis-shield/firewall/blocklist.json';
const BLOCK_SCRIPT = '/usr/local/bin/aegis-shield-block';

/**
 * FirewallIntegration class provides methods to interact with the system firewall
 */
class FirewallIntegration {
  /**
   * Create a firewall integration instance
   * @param {Object} config - Configuration object
   */
  constructor(config) {
    this.config = config;
    this.logger = config.logger || console;
    this.enabled = config.integration && config.integration.firewall && config.integration.firewall.enabled || false;
    this.firewall_type = (config.integration && config.integration.firewall && config.integration.firewall.type) || 'nftables';
    this.blockList = new Map();
    this.initialized = false;
    
    // Make sure we're using nftables
    if (this.firewall_type !== 'nftables') {
      this.logger.warn('Firewall type is not set to nftables. Forcing to nftables as it is the only supported type in this version.');
      this.firewall_type = 'nftables';
    }
  }

  /**
   * Initialize the firewall integration
   * @returns {Promise<boolean>} True if initialization was successful
   */
  async initialize() {
    if (!this.enabled) {
      this.logger.info('Firewall integration is disabled');
      return false;
    }

    this.logger.info(`Initializing firewall integration with ${this.firewall_type}`);
    
    try {
      // Check if nftables is installed
      await this.executeCommand('which nft');
      
      // Create the firewall directory if it doesn't exist
      const firewallDir = path.dirname(BLOCKLIST_PATH);
      if (!fs.existsSync(firewallDir)) {
        fs.mkdirSync(firewallDir, { recursive: true });
      }
      
      // Check if helper script exists, if not create it
      if (!fs.existsSync(BLOCK_SCRIPT)) {
        await this.createBlockingScript();
      }
      
      // Load existing blocklist
      await this.loadBlocklist();
      
      // Check if the aegis-shield tables are initialized
      const tables = await this.executeCommand('nft list tables');
      if (!tables.includes('aegis-shield')) {
        this.logger.warn('The nftables aegis-shield table is not configured. Running firewall setup script...');
        
        // Try to find the nftables configuration script
        const scriptPath = '/etc/aegis-shield/firewall/nftables-config-fixed.sh';
        if (fs.existsSync(scriptPath)) {
          this.logger.info('Running nftables configuration script...');
          await this.executeCommand(`bash ${scriptPath}`);
        } else {
          this.logger.error('nftables configuration script not found. Please run the script manually.');
          return false;
        }
      }
      
      this.initialized = true;
      this.logger.info('Firewall integration initialized successfully');
      return true;
    } catch (error) {
      this.logger.error(`Failed to initialize firewall integration: ${error.message}`);
      return false;
    }
  }

  /**
   * Create the blocking script if it doesn't exist
   * @returns {Promise<void>}
   */
  async createBlockingScript() {
    this.logger.info('Creating nftables blocking script');
    
    // Simple version of the blocking script (minimal implementation)
    const scriptContent = `#!/bin/bash
# Aegis Shield IP Blocking Script (Minimal)

if [ $# -lt 2 ]; then
    echo "Usage: $0 [block|unblock] IP"
    exit 1
fi

ACTION="$1"
IP="$2"

if [ "$ACTION" = "block" ]; then
    # Check if IPv6
    if [[ "$IP" =~ .*:.* ]]; then
        nft add element inet aegis-shield blocked_ips6 { $IP }
    else
        nft add element inet aegis-shield blocked_ips { $IP }
    fi
    echo "Blocked $IP"
elif [ "$ACTION" = "unblock" ]; then
    # Check if IPv6
    if [[ "$IP" =~ .*:.* ]]; then
        nft delete element inet aegis-shield blocked_ips6 { $IP }
    else
        nft delete element inet aegis-shield blocked_ips { $IP }
    fi
    echo "Unblocked $IP"
else
    echo "Invalid action: $ACTION"
    echo "Use 'block' or 'unblock'"
    exit 1
fi
`;

    fs.writeFileSync(BLOCK_SCRIPT, scriptContent, { mode: 0o755 });
    await this.executeCommand(`chmod +x ${BLOCK_SCRIPT}`);
    this.logger.info('Created blocking script');
  }

  /**
   * Load the blocklist from disk
   * @returns {Promise<void>}
   */
  async loadBlocklist() {
    try {
      if (fs.existsSync(BLOCKLIST_PATH)) {
        const data = JSON.parse(fs.readFileSync(BLOCKLIST_PATH, 'utf8'));
        
        // Convert to Map for efficient operations
        this.blockList = new Map();
        for (const [ip, details] of Object.entries(data)) {
          this.blockList.set(ip, details);
        }
        
        this.logger.info(`Loaded ${this.blockList.size} entries from blocklist`);
      } else {
        this.logger.info('No existing blocklist found, starting with empty list');
        this.blockList = new Map();
      }
    } catch (error) {
      this.logger.error(`Failed to load blocklist: ${error.message}`);
      this.blockList = new Map();
    }
  }

  /**
   * Save the blocklist to disk
   * @returns {Promise<void>}
   */
  async saveBlocklist() {
    try {
      const blockListObj = Object.fromEntries(this.blockList);
      fs.writeFileSync(BLOCKLIST_PATH, JSON.stringify(blockListObj, null, 2));
      this.logger.debug(`Saved ${this.blockList.size} entries to blocklist`);
    } catch (error) {
      this.logger.error(`Failed to save blocklist: ${error.message}`);
    }
  }

  /**
   * Block an IP address
   * @param {string} ip - IP address to block
   * @param {string} reason - Reason for blocking
   * @param {number} duration - Duration in seconds (0 for permanent)
   * @returns {Promise<boolean>} True if successful
   */
  async blockIP(ip, reason, duration = 0) {
    if (!this.initialized || !this.enabled) {
      this.logger.warn('Firewall integration is not initialized or disabled');
      return false;
    }
    
    if (!ip || typeof ip !== 'string') {
      this.logger.error('Invalid IP address');
      return false;
    }
    
    try {
      let command = `${BLOCK_SCRIPT} block ${ip}`;
      
      // Add timeout if specified
      if (duration > 0) {
        command = `nft add element inet aegis-shield blocked_ips { ${ip} timeout ${duration}s }`;
      }
      
      await this.executeCommand(command);
      
      // Update our internal blocklist
      this.blockList.set(ip, {
        reason: reason || 'Manual block',
        timestamp: Date.now(),
        expires: duration > 0 ? Date.now() + (duration * 1000) : 0
      });
      
      await this.saveBlocklist();
      this.logger.info(`Blocked IP ${ip}: ${reason}`);
      return true;
    } catch (error) {
      this.logger.error(`Failed to block IP ${ip}: ${error.message}`);
      return false;
    }
  }

  /**
   * Unblock an IP address
   * @param {string} ip - IP address to unblock
   * @returns {Promise<boolean>} True if successful
   */
  async unblockIP(ip) {
    if (!this.initialized || !this.enabled) {
      this.logger.warn('Firewall integration is not initialized or disabled');
      return false;
    }
    
    if (!ip || typeof ip !== 'string') {
      this.logger.error('Invalid IP address');
      return false;
    }
    
    try {
      const command = `${BLOCK_SCRIPT} unblock ${ip}`;
      await this.executeCommand(command);
      
      // Update our internal blocklist
      this.blockList.delete(ip);
      await this.saveBlocklist();
      
      this.logger.info(`Unblocked IP ${ip}`);
      return true;
    } catch (error) {
      this.logger.error(`Failed to unblock IP ${ip}: ${error.message}`);
      return false;
    }
  }

  /**
   * Apply the blocklist to the firewall
   * @returns {Promise<boolean>} True if successful
   */
  async applyBlocklist() {
    if (!this.initialized || !this.enabled) {
      this.logger.warn('Firewall integration is not initialized or disabled');
      return false;
    }
    
    try {
      this.logger.info('Applying blocklist to nftables');
      
      // Get the current sets for comparison
      const currentIpv4Blocks = await this.getBlockedIPs();
      const currentIpv6Blocks = await this.getBlockedIPs(true);
      
      // Apply changes in batches for better performance
      const ipv4Batch = [];
      const ipv6Batch = [];
      
      // Check for expired entries and remove them from our blocklist
      const now = Date.now();
      for (const [ip, details] of this.blockList.entries()) {
        if (details.expires > 0 && details.expires <= now) {
          this.blockList.delete(ip);
          continue;
        }
        
        // Skip if already in the set (to avoid unnecessary updates)
        if (ip.includes(':')) {
          if (!currentIpv6Blocks.includes(ip)) {
            ipv6Batch.push(ip);
          }
        } else {
          if (!currentIpv4Blocks.includes(ip)) {
            ipv4Batch.push(ip);
          }
        }
      }
      
      // Apply IPv4 blocks in batch
      if (ipv4Batch.length > 0) {
        const items = ipv4Batch.map(ip => `${ip}`).join(', ');
        const command = `nft add element inet aegis-shield blocked_ips { ${items} }`;
        await this.executeCommand(command);
        this.logger.info(`Applied ${ipv4Batch.length} IPv4 blocks`);
      }
      
      // Apply IPv6 blocks in batch
      if (ipv6Batch.length > 0) {
        const items = ipv6Batch.map(ip => `${ip}`).join(', ');
        const command = `nft add element inet aegis-shield blocked_ips6 { ${items} }`;
        await this.executeCommand(command);
        this.logger.info(`Applied ${ipv6Batch.length} IPv6 blocks`);
      }
      
      // Save our updated blocklist
      await this.saveBlocklist();
      
      return true;
    } catch (error) {
      this.logger.error(`Failed to apply blocklist: ${error.message}`);
      return false;
    }
  }

  /**
   * Get the current ruleset
   * @returns {Promise<string>} The current ruleset
   */
  async getRuleset() {
    if (!this.initialized || !this.enabled) {
      return '';
    }
    
    try {
      const { stdout } = await execAsync('nft list ruleset');
      return stdout;
    } catch (error) {
      this.logger.error(`Failed to get nftables ruleset: ${error.message}`);
      return '';
    }
  }

  /**
   * Block a network range
   * @param {string} network - Network range in CIDR notation
   * @param {string} reason - Reason for blocking
   * @returns {Promise<boolean>} True if successful
   */
  async blockNetwork(network, reason) {
    if (!this.initialized || !this.enabled) {
      this.logger.warn('Firewall integration is not initialized or disabled');
      return false;
    }
    
    if (!network || typeof network !== 'string' || !network.includes('/')) {
      this.logger.error('Invalid network CIDR format');
      return false;
    }
    
    try {
      // Determine if IPv4 or IPv6
      let command;
      if (network.includes(':')) {
        command = `nft add element inet aegis-shield blocked_nets6 { ${network} }`;
      } else {
        command = `nft add element inet aegis-shield blocked_nets { ${network} }`;
      }
      
      await this.executeCommand(command);
      
      // Update our internal blocklist with network prefix
      this.blockList.set(`net:${network}`, {
        reason: reason || 'Manual block',
        timestamp: Date.now(),
        expires: 0,
        isNetwork: true
      });
      
      await this.saveBlocklist();
      this.logger.info(`Blocked network ${network}: ${reason}`);
      return true;
    } catch (error) {
      this.logger.error(`Failed to block network ${network}: ${error.message}`);
      return false;
    }
  }

  /**
   * Execute a shell command
   * @param {string} command - Command to execute
   * @returns {Promise<string>} Command output
   */
  async executeCommand(command) {
    try {
      const { stdout, stderr } = await execAsync(command);
      if (stderr) {
        this.logger.debug(`Command stderr: ${stderr}`);
      }
      return stdout.trim();
    } catch (error) {
      this.logger.error(`Command execution failed: ${error.message}`);
      throw error;
    }
  }

  /**
   * Get list of currently blocked IPs from nftables
   * @param {boolean} ipv6 - Whether to get IPv6 addresses
   * @returns {Promise<string[]>} Array of blocked IPs
   */
  async getBlockedIPs(ipv6 = false) {
    try {
      const setName = ipv6 ? 'blocked_ips6' : 'blocked_ips';
      const output = await this.executeCommand(`nft list set inet aegis-shield ${setName}`);
      
      // Parse the output to extract IP addresses
      const regex = ipv6 ? /([0-9a-fA-F:]+)(?:\s|,|$)/g : /(\d+\.\d+\.\d+\.\d+)(?:\s|,|$)/g;
      const matches = output.match(regex) || [];
      
      // Clean up the matches
      return matches.map(ip => ip.trim().replace(/,$/g, ''));
    } catch (error) {
      this.logger.error(`Failed to get blocked IPs: ${error.message}`);
      return [];
    }
  }
  
  /**
   * Check if an IP is currently blocked
   * @param {string} ip - IP address to check
   * @returns {Promise<boolean>} True if the IP is blocked
   */
  async isIPBlocked(ip) {
    if (!this.initialized || !this.enabled) {
      return false;
    }
    
    try {
      const ipv6 = ip.includes(':');
      const blockedIPs = await this.getBlockedIPs(ipv6);
      return blockedIPs.includes(ip);
    } catch (error) {
      this.logger.error(`Failed to check if IP is blocked: ${error.message}`);
      return false;
    }
  }
  
  /**
   * Clear all blocked IPs
   * @returns {Promise<boolean>} True if successful
   */
  async clearAllBlocks() {
    if (!this.initialized || !this.enabled) {
      this.logger.warn('Firewall integration is not initialized or disabled');
      return false;
    }
    
    try {
      // Clear IPv4 blocks
      await this.executeCommand('nft flush set inet aegis-shield blocked_ips');
      
      // Clear IPv6 blocks
      await this.executeCommand('nft flush set inet aegis-shield blocked_ips6');
      
      // Clear network blocks
      await this.executeCommand('nft flush set inet aegis-shield blocked_nets');
      await this.executeCommand('nft flush set inet aegis-shield blocked_nets6');
      
      // Clear our internal blocklist
      this.blockList.clear();
      await this.saveBlocklist();
      
      this.logger.info('Cleared all blocked IPs and networks');
      return true;
    } catch (error) {
      this.logger.error(`Failed to clear all blocks: ${error.message}`);
      return false;
    }
  }
}

module.exports = FirewallIntegration; 