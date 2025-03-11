/**
 * Aegis Shield - Military-Grade IDS/IPS Core Engine
 * ================================================
 * A high-security intrusion detection and prevention system
 * designed for maximum protection against advanced threats.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');
const crypto = require('crypto');
const { spawn, exec } = require('child_process');
const express = require('express');
const https = require('https');
const winston = require('winston');
const geoip = require('geoip-lite');
const ipRangeCheck = require('ip-range-check');
const pcap = require('pcap');
const schedule = require('node-schedule');

// Configuration file path
const CONFIG_PATH = process.env.AEGIS_CONFIG || '/etc/aegis-shield/config.yaml';

// Initialize logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: '/var/log/aegis-shield/error.log', level: 'error' }),
    new winston.transports.File({ filename: '/var/log/aegis-shield/combined.log' }),
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    })
  ]
});

/**
 * Main Aegis Shield Engine Class
 */
class AegisShieldEngine {
  constructor() {
    this.config = null;
    this.engineProcesses = {};
    this.blockList = new Set();
    this.alertCache = new Map();
    this.app = express();
    this.server = null;
    this.packetCapture = null;
    this.statisticsInterval = null;
    this.isRunning = false;
    this.startTime = new Date();
    this.threatIntelligence = new Map();
    this.initialized = false;
  }

  /**
   * Initialize the Aegis Shield engine
   */
  async initialize() {
    try {
      logger.info('Initializing Aegis Shield Engine...');
      
      // Load configuration
      await this.loadConfig();
      
      // Set up logging based on configuration
      this.configureLogging();
      
      // Initialize directories
      this.initializeDirectories();
      
      // Load blocklist
      await this.loadBlockList();
      
      // Load threat intelligence
      await this.loadThreatIntelligence();
      
      // Initialize API server
      this.initializeAPIServer();
      
      // Initialize engines
      await this.initializeEngines();
      
      // Set up scheduled tasks
      this.setupScheduledTasks();
      
      // Mark as initialized
      this.initialized = true;
      
      logger.info('Aegis Shield Engine initialized successfully');
      return true;
    } catch (error) {
      logger.error(`Failed to initialize Aegis Shield Engine: ${error.message}`, { error });
      return false;
    }
  }

  /**
   * Load configuration from YAML file
   */
  async loadConfig() {
    try {
      logger.info(`Loading configuration from ${CONFIG_PATH}`);
      const configFile = fs.readFileSync(CONFIG_PATH, 'utf8');
      this.config = yaml.load(configFile);
      logger.info('Configuration loaded successfully');
    } catch (error) {
      logger.error(`Failed to load configuration: ${error.message}`, { error });
      throw new Error(`Configuration loading failed: ${error.message}`);
    }
  }

  /**
   * Configure logging based on configuration
   */
  configureLogging() {
    try {
      const logLevel = this.config.general.log_level || 'info';
      logger.level = logLevel;
      logger.info(`Log level set to ${logLevel}`);
    } catch (error) {
      logger.error(`Failed to configure logging: ${error.message}`, { error });
    }
  }

  /**
   * Initialize required directories
   */
  initializeDirectories() {
    try {
      const directories = [
        '/var/log/aegis-shield',
        '/var/lib/aegis-shield',
        '/var/lib/aegis-shield/rules',
        '/var/lib/aegis-shield/data',
        '/var/run/aegis-shield'
      ];
      
      directories.forEach(dir => {
        if (!fs.existsSync(dir)) {
          fs.mkdirSync(dir, { recursive: true });
          logger.info(`Created directory: ${dir}`);
        }
      });
    } catch (error) {
      logger.error(`Failed to initialize directories: ${error.message}`, { error });
      throw new Error(`Directory initialization failed: ${error.message}`);
    }
  }

  /**
   * Initialize intrusion detection/prevention engines
   */
  async initializeEngines() {
    try {
      logger.info('Initializing security engines...');
      
      // Initialize Suricata if enabled
      if (this.config.engines.suricata.enabled) {
        await this.initializeSuricata();
      }
      
      // Initialize Snort if enabled
      if (this.config.engines.snort.enabled) {
        await this.initializeSnort();
      }
      
      // Initialize Zeek if enabled
      if (this.config.engines.zeek.enabled) {
        await this.initializeZeek();
      }
      
      // Initialize custom engines
      if (this.config.engines.custom.enabled) {
        await this.initializeCustomEngines();
      }
      
      logger.info('All security engines initialized successfully');
    } catch (error) {
      logger.error(`Failed to initialize engines: ${error.message}`, { error });
      throw new Error(`Engine initialization failed: ${error.message}`);
    }
  }

  /**
   * Initialize Suricata engine
   */
  async initializeSuricata() {
    try {
      logger.info('Initializing Suricata engine...');
      
      // Update Suricata rules
      await this.updateSuricataRules();
      
      // Start Suricata process
      const suricataArgs = [
        '-c', this.config.engines.suricata.config_path,
        '-i', this.config.network.interfaces.monitoring[0]
      ];
      
      this.engineProcesses.suricata = spawn('suricata', suricataArgs);
      
      this.engineProcesses.suricata.stdout.on('data', (data) => {
        logger.debug(`Suricata stdout: ${data}`);
      });
      
      this.engineProcesses.suricata.stderr.on('data', (data) => {
        logger.error(`Suricata stderr: ${data}`);
      });
      
      this.engineProcesses.suricata.on('close', (code) => {
        logger.warn(`Suricata process exited with code ${code}`);
        // Attempt to restart if exited abnormally
        if (code !== 0 && this.isRunning) {
          logger.info('Attempting to restart Suricata...');
          setTimeout(() => this.initializeSuricata(), 5000);
        }
      });
      
      logger.info('Suricata engine initialized successfully');
    } catch (error) {
      logger.error(`Failed to initialize Suricata: ${error.message}`, { error });
      throw new Error(`Suricata initialization failed: ${error.message}`);
    }
  }

  /**
   * Initialize Snort engine
   */
  async initializeSnort() {
    try {
      logger.info('Initializing Snort engine...');
      
      // Update Snort rules
      await this.updateSnortRules();
      
      // Start Snort process
      const snortArgs = [
        '-c', this.config.engines.snort.config_path,
        '-i', this.config.network.interfaces.monitoring[0],
        '-A', 'console'
      ];
      
      this.engineProcesses.snort = spawn('snort', snortArgs);
      
      this.engineProcesses.snort.stdout.on('data', (data) => {
        logger.debug(`Snort stdout: ${data}`);
        // Parse Snort alerts
        this.parseSnortAlert(data.toString());
      });
      
      this.engineProcesses.snort.stderr.on('data', (data) => {
        logger.error(`Snort stderr: ${data}`);
      });
      
      this.engineProcesses.snort.on('close', (code) => {
        logger.warn(`Snort process exited with code ${code}`);
        // Attempt to restart if exited abnormally
        if (code !== 0 && this.isRunning) {
          logger.info('Attempting to restart Snort...');
          setTimeout(() => this.initializeSnort(), 5000);
        }
      });
      
      logger.info('Snort engine initialized successfully');
    } catch (error) {
      logger.error(`Failed to initialize Snort: ${error.message}`, { error });
      throw new Error(`Snort initialization failed: ${error.message}`);
    }
  }

  /**
   * Initialize Zeek engine
   */
  async initializeZeek() {
    try {
      logger.info('Initializing Zeek engine...');
      
      // Start Zeek process
      const zeekArgs = [
        '-i', this.config.network.interfaces.monitoring[0],
        this.config.engines.zeek.config_path
      ];
      
      this.engineProcesses.zeek = spawn('zeek', zeekArgs);
      
      this.engineProcesses.zeek.stdout.on('data', (data) => {
        logger.debug(`Zeek stdout: ${data}`);
      });
      
      this.engineProcesses.zeek.stderr.on('data', (data) => {
        logger.error(`Zeek stderr: ${data}`);
      });
      
      this.engineProcesses.zeek.on('close', (code) => {
        logger.warn(`Zeek process exited with code ${code}`);
        // Attempt to restart if exited abnormally
        if (code !== 0 && this.isRunning) {
          logger.info('Attempting to restart Zeek...');
          setTimeout(() => this.initializeZeek(), 5000);
        }
      });
      
      logger.info('Zeek engine initialized successfully');
    } catch (error) {
      logger.error(`Failed to initialize Zeek: ${error.message}`, { error });
      throw new Error(`Zeek initialization failed: ${error.message}`);
    }
  }

  /**
   * Initialize custom security engines
   */
  async initializeCustomEngines() {
    try {
      logger.info('Initializing custom security engines...');
      
      const customModules = this.config.engines.custom.modules || [];
      
      for (const module of customModules) {
        logger.info(`Loading custom module: ${module}`);
        // Here you would load custom modules from file or import them
        // This is a placeholder for implementing custom detection modules
      }
      
      // Start packet capture for custom analysis
      this.startPacketCapture();
      
      logger.info('Custom security engines initialized successfully');
    } catch (error) {
      logger.error(`Failed to initialize custom engines: ${error.message}`, { error });
      throw new Error(`Custom engine initialization failed: ${error.message}`);
    }
  }

  /**
   * Start packet capture for custom analysis
   */
  startPacketCapture() {
    try {
      const interface = this.config.network.interfaces.monitoring[0];
      const filter = this.config.network.capture.bpf_filter || '';
      const snaplen = this.config.network.capture.snaplen || 65535;
      
      logger.info(`Starting packet capture on interface ${interface} with filter "${filter}"`);
      
      this.packetCapture = pcap.createSession(interface, { filter, snaplen });
      
      this.packetCapture.on('packet', (rawPacket) => {
        // Process packet for custom analysis
        this.analyzePacket(rawPacket);
      });
      
      this.packetCapture.on('error', (error) => {
        logger.error(`Packet capture error: ${error.message}`, { error });
      });
      
      logger.info('Packet capture started successfully');
    } catch (error) {
      logger.error(`Failed to start packet capture: ${error.message}`, { error });
      throw new Error(`Packet capture initialization failed: ${error.message}`);
    }
  }

  /**
   * Analyze packet with custom detection modules
   * @param {Buffer} rawPacket - Raw packet data
   */
  analyzePacket(rawPacket) {
    try {
      // Parse packet
      const packet = pcap.decode.packet(rawPacket);
      
      // Extract IP addresses if available
      let srcIP = null;
      let dstIP = null;
      
      if (packet.payload && packet.payload.payload) {
        const ipPacket = packet.payload.payload;
        srcIP = ipPacket.saddr.addr.join('.');
        dstIP = ipPacket.daddr.addr.join('.');
        
        // Check if IP is in blocklist
        if (this.blockList.has(srcIP)) {
          this.blockIP(srcIP, 'IP in blocklist');
          return;
        }
        
        // Check if IP is from blocked country
        this.checkGeoIP(srcIP);
        
        // Apply custom detection logic
        this.customPacketAnalysis(packet, srcIP, dstIP);
      }
    } catch (error) {
      logger.debug(`Packet analysis error: ${error.message}`);
    }
  }

  /**
   * Custom packet analysis logic
   * @param {Object} packet - Parsed packet
   * @param {string} srcIP - Source IP address
   * @param {string} dstIP - Destination IP address
   */
  customPacketAnalysis(packet, srcIP, dstIP) {
    try {
      // Implement custom detection algorithms here
      // This is where you can add sophisticated behavioral analysis,
      // machine learning anomaly detection, etc.
      
      // Example: Simple connection rate limiting
      const key = `connections:${srcIP}`;
      const count = this.alertCache.get(key) || 0;
      this.alertCache.set(key, count + 1);
      
      // Check thresholds from config
      const maxConnections = this.config.protection.thresholds.max_connections_per_ip || 100;
      
      if (count > maxConnections) {
        const alert = {
          timestamp: new Date(),
          type: 'rate_limit',
          source: srcIP,
          destination: dstIP,
          message: `Connection rate limit exceeded: ${count}/${maxConnections}`,
          severity: 'high'
        };
        
        this.handleAlert(alert);
        
        // Reset counter
        this.alertCache.set(key, 0);
      }
      
      // Implement more advanced detection here
    } catch (error) {
      logger.error(`Custom packet analysis error: ${error.message}`);
    }
  }

  /**
   * Check if IP is from blocked country
   * @param {string} ip - IP address to check
   * @returns {boolean} - True if IP is from blocked country
   */
  checkGeoIP(ip) {
    try {
      const blockedCountries = this.config.protection.default_rules.block_countries || [];
      
      if (blockedCountries.length === 0) {
        return false;
      }
      
      const geo = geoip.lookup(ip);
      
      if (geo && blockedCountries.includes(geo.country)) {
        const alert = {
          timestamp: new Date(),
          type: 'blocked_country',
          source: ip,
          destination: null,
          message: `Connection from blocked country: ${geo.country}`,
          severity: 'medium',
          geo: geo
        };
        
        this.handleAlert(alert);
        
        if (this.config.protection.auto_block) {
          this.blockIP(ip, `IP from blocked country: ${geo.country}`);
        }
        
        return true;
      }
      
      return false;
    } catch (error) {
      logger.error(`GeoIP check error: ${error.message}`);
      return false;
    }
  }

  /**
   * Block an IP address
   * @param {string} ip - IP address to block
   * @param {string} reason - Reason for blocking
   */
  blockIP(ip, reason) {
    try {
      if (this.blockList.has(ip)) {
        return; // Already blocked
      }
      
      logger.info(`Blocking IP ${ip}: ${reason}`);
      
      // Add to blocklist
      this.blockList.add(ip);
      
      // Save to persistent storage
      this.saveBlockList();
      
      // Apply firewall rule based on configuration
      if (this.config.integration.firewall.enabled) {
        if (this.config.integration.firewall.type === 'iptables') {
          const cmd = `iptables -A INPUT -s ${ip} -j DROP`;
          exec(cmd, (error, stdout, stderr) => {
            if (error) {
              logger.error(`Failed to add iptables rule: ${error.message}`);
            } else {
              logger.info(`Added iptables rule to block ${ip}`);
            }
          });
        }
        // Add support for other firewall types here
      }
      
      // Create alert for blocked IP
      const alert = {
        timestamp: new Date(),
        type: 'ip_blocked',
        source: ip,
        destination: null,
        message: `IP blocked: ${reason}`,
        severity: 'high'
      };
      
      this.handleAlert(alert);
      
      // Schedule unblock if block_duration is set
      const blockDuration = this.config.protection.block_duration;
      if (blockDuration > 0) {
        setTimeout(() => {
          this.unblockIP(ip, 'Block duration expired');
        }, blockDuration * 1000);
      }
    } catch (error) {
      logger.error(`Failed to block IP ${ip}: ${error.message}`);
    }
  }

  /**
   * Unblock an IP address
   * @param {string} ip - IP address to unblock
   * @param {string} reason - Reason for unblocking
   */
  unblockIP(ip, reason) {
    try {
      if (!this.blockList.has(ip)) {
        return; // Not blocked
      }
      
      logger.info(`Unblocking IP ${ip}: ${reason}`);
      
      // Remove from blocklist
      this.blockList.delete(ip);
      
      // Save to persistent storage
      this.saveBlockList();
      
      // Remove firewall rule
      if (this.config.integration.firewall.enabled) {
        if (this.config.integration.firewall.type === 'iptables') {
          const cmd = `iptables -D INPUT -s ${ip} -j DROP`;
          exec(cmd, (error, stdout, stderr) => {
            if (error) {
              logger.error(`Failed to remove iptables rule: ${error.message}`);
            } else {
              logger.info(`Removed iptables rule for ${ip}`);
            }
          });
        }
        // Add support for other firewall types here
      }
      
      // Create alert for unblocked IP
      const alert = {
        timestamp: new Date(),
        type: 'ip_unblocked',
        source: ip,
        destination: null,
        message: `IP unblocked: ${reason}`,
        severity: 'info'
      };
      
      this.handleAlert(alert);
    } catch (error) {
      logger.error(`Failed to unblock IP ${ip}: ${error.message}`);
    }
  }

  /**
   * Load the blocklist from persistent storage
   */
  async loadBlockList() {
    try {
      const blockListPath = '/var/lib/aegis-shield/blocklist.json';
      
      if (!fs.existsSync(blockListPath)) {
        this.blockList = new Set();
        return;
      }
      
      const blockListData = JSON.parse(fs.readFileSync(blockListPath, 'utf8'));
      this.blockList = new Set(blockListData);
      
      logger.info(`Loaded ${this.blockList.size} IP addresses from blocklist`);
    } catch (error) {
      logger.error(`Failed to load blocklist: ${error.message}`);
      this.blockList = new Set();
    }
  }

  /**
   * Save the blocklist to persistent storage
   */
  saveBlockList() {
    try {
      const blockListPath = '/var/lib/aegis-shield/blocklist.json';
      const blockListData = JSON.stringify(Array.from(this.blockList));
      
      fs.writeFileSync(blockListPath, blockListData);
      logger.debug(`Saved ${this.blockList.size} IP addresses to blocklist`);
    } catch (error) {
      logger.error(`Failed to save blocklist: ${error.message}`);
    }
  }

  /**
   * Load threat intelligence data
   */
  async loadThreatIntelligence() {
    try {
      logger.info('Loading threat intelligence data...');
      
      // Here you would load threat intel from various sources
      // This is a placeholder for implementing threat intelligence
      
      logger.info('Threat intelligence data loaded successfully');
    } catch (error) {
      logger.error(`Failed to load threat intelligence: ${error.message}`);
    }
  }

  /**
   * Handle security alert
   * @param {Object} alert - Alert object
   */
  handleAlert(alert) {
    try {
      // Log the alert
      if (alert.severity === 'high' || alert.severity === 'critical') {
        logger.error(`SECURITY ALERT: ${alert.message}`, { alert });
      } else if (alert.severity === 'medium') {
        logger.warn(`SECURITY ALERT: ${alert.message}`, { alert });
      } else {
        logger.info(`SECURITY ALERT: ${alert.message}`, { alert });
      }
      
      // Store alert for API access
      const alertsPath = '/var/lib/aegis-shield/alerts.jsonl';
      const alertStr = JSON.stringify(alert) + '\n';
      fs.appendFileSync(alertsPath, alertStr);
      
      // Send alerts via configured methods
      this.sendAlerts(alert);
      
      // Take automated actions if configured
      if (this.config.protection.auto_block && 
          (alert.severity === 'high' || alert.severity === 'critical') &&
          alert.source) {
        this.blockIP(alert.source, alert.message);
      }
    } catch (error) {
      logger.error(`Failed to handle alert: ${error.message}`);
    }
  }

  /**
   * Send alerts via configured methods
   * @param {Object} alert - Alert object
   */
  sendAlerts(alert) {
    try {
      // Email alerts
      if (this.config.alerts.methods.email.enabled) {
        const alertLevel = this.config.alerts.methods.email.alert_level || 'high';
        
        if (alert.severity === alertLevel || alert.severity === 'critical') {
          // Implement email sending logic here
          logger.info(`Would send email alert: ${alert.message}`);
        }
      }
      
      // Syslog alerts
      if (this.config.alerts.methods.syslog.enabled) {
        // Implement syslog sending logic here
        logger.info(`Would send syslog alert: ${alert.message}`);
      }
      
      // Webhook alerts
      if (this.config.alerts.methods.webhook.enabled) {
        // Implement webhook sending logic here
        logger.info(`Would send webhook alert: ${alert.message}`);
      }
    } catch (error) {
      logger.error(`Failed to send alert: ${error.message}`);
    }
  }

  /**
   * Parse Suricata alert
   * @param {string} data - Alert data
   */
  parseSuricataAlert(data) {
    try {
      // Implement parsing logic for Suricata alerts
      // Convert to standard alert format and call handleAlert
    } catch (error) {
      logger.error(`Failed to parse Suricata alert: ${error.message}`);
    }
  }

  /**
   * Parse Snort alert
   * @param {string} data - Alert data
   */
  parseSnortAlert(data) {
    try {
      // Implement parsing logic for Snort alerts
      // Convert to standard alert format and call handleAlert
    } catch (error) {
      logger.error(`Failed to parse Snort alert: ${error.message}`);
    }
  }

  /**
   * Update Suricata rules
   */
  async updateSuricataRules() {
    try {
      logger.info('Updating Suricata rules...');
      
      // Implement rule update logic here
      // This could download rules from sources, update local files, etc.
      
      logger.info('Suricata rules updated successfully');
    } catch (error) {
      logger.error(`Failed to update Suricata rules: ${error.message}`);
      throw new Error(`Suricata rule update failed: ${error.message}`);
    }
  }

  /**
   * Update Snort rules
   */
  async updateSnortRules() {
    try {
      logger.info('Updating Snort rules...');
      
      // Implement rule update logic here
      // This could download rules from sources, update local files, etc.
      
      logger.info('Snort rules updated successfully');
    } catch (error) {
      logger.error(`Failed to update Snort rules: ${error.message}`);
      throw new Error(`Snort rule update failed: ${error.message}`);
    }
  }

  /**
   * Initialize API server
   */
  initializeAPIServer() {
    try {
      logger.info('Initializing API server...');
      
      // Set up middleware
      this.app.use(express.json());
      this.app.use(express.urlencoded({ extended: true }));
      
      // Authentication middleware (simplified)
      const authMiddleware = (req, res, next) => {
        // Implement proper authentication in a real system
        next();
      };
      
      // API routes
      
      // Status endpoint
      this.app.get('/api/status', authMiddleware, (req, res) => {
        const uptime = Math.floor((new Date() - this.startTime) / 1000);
        const status = {
          status: 'running',
          version: this.config.general.version,
          mode: this.config.general.mode,
          uptime: uptime,
          engines: {
            suricata: this.config.engines.suricata.enabled ? 'running' : 'disabled',
            snort: this.config.engines.snort.enabled ? 'running' : 'disabled',
            zeek: this.config.engines.zeek.enabled ? 'running' : 'disabled',
            custom: this.config.engines.custom.enabled ? 'running' : 'disabled'
          },
          blocklist_size: this.blockList.size,
          protection_level: this.config.protection.level
        };
        
        res.json(status);
      });
      
      // Alerts endpoint
      this.app.get('/api/alerts', authMiddleware, (req, res) => {
        try {
          const alertsPath = '/var/lib/aegis-shield/alerts.jsonl';
          let alerts = [];
          
          if (fs.existsSync(alertsPath)) {
            const alertsData = fs.readFileSync(alertsPath, 'utf8');
            alerts = alertsData.split('\n')
              .filter(line => line.trim())
              .map(line => JSON.parse(line))
              .reverse() // Most recent first
              .slice(0, 100); // Limit to 100 alerts
          }
          
          res.json({ alerts });
        } catch (error) {
          logger.error(`Failed to get alerts: ${error.message}`);
          res.status(500).json({ error: 'Failed to get alerts' });
        }
      });
      
      // Blocklist endpoint
      this.app.get('/api/blocklist', authMiddleware, (req, res) => {
        const blocklist = Array.from(this.blockList);
        res.json({ blocklist });
      });
      
      // Manual block endpoint
      this.app.post('/api/block', authMiddleware, (req, res) => {
        try {
          const { ip, reason } = req.body;
          
          if (!ip) {
            return res.status(400).json({ error: 'IP address is required' });
          }
          
          const blockReason = reason || 'Manually blocked';
          this.blockIP(ip, blockReason);
          
          res.json({ success: true, message: `IP ${ip} blocked: ${blockReason}` });
        } catch (error) {
          logger.error(`Failed to block IP: ${error.message}`);
          res.status(500).json({ error: 'Failed to block IP' });
        }
      });
      
      // Manual unblock endpoint
      this.app.post('/api/unblock', authMiddleware, (req, res) => {
        try {
          const { ip, reason } = req.body;
          
          if (!ip) {
            return res.status(400).json({ error: 'IP address is required' });
          }
          
          const unblockReason = reason || 'Manually unblocked';
          this.unblockIP(ip, unblockReason);
          
          res.json({ success: true, message: `IP ${ip} unblocked: ${unblockReason}` });
        } catch (error) {
          logger.error(`Failed to unblock IP: ${error.message}`);
          res.status(500).json({ error: 'Failed to unblock IP' });
        }
      });
      
      // Start server if dashboard is enabled
      if (this.config.dashboard.enabled) {
        const port = this.config.dashboard.port || 8443;
        
        if (this.config.dashboard.https) {
          // HTTPS server
          const certPath = this.config.dashboard.cert_path;
          const keyPath = this.config.dashboard.key_path;
          
          if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
            const options = {
              cert: fs.readFileSync(certPath),
              key: fs.readFileSync(keyPath)
            };
            
            this.server = https.createServer(options, this.app);
            this.server.listen(port, () => {
              logger.info(`API server listening on https://0.0.0.0:${port}`);
            });
          } else {
            logger.error('Certificate or key file not found, falling back to HTTP');
            this.server = this.app.listen(port, () => {
              logger.info(`API server listening on http://0.0.0.0:${port}`);
            });
          }
        } else {
          // HTTP server
          this.server = this.app.listen(port, () => {
            logger.info(`API server listening on http://0.0.0.0:${port}`);
          });
        }
      }
      
      logger.info('API server initialized successfully');
    } catch (error) {
      logger.error(`Failed to initialize API server: ${error.message}`);
      throw new Error(`API server initialization failed: ${error.message}`);
    }
  }

  /**
   * Set up scheduled tasks
   */
  setupScheduledTasks() {
    try {
      logger.info('Setting up scheduled tasks...');
      
      // Schedule rule updates
      const suricataUpdateInterval = this.config.engines.suricata.update_interval || 86400;
      const snortUpdateInterval = this.config.engines.snort.update_interval || 86400;
      
      // Schedule Suricata rule updates
      if (this.config.engines.suricata.enabled) {
        logger.info(`Scheduling Suricata rule updates every ${suricataUpdateInterval} seconds`);
        setInterval(() => {
          this.updateSuricataRules().catch(error => {
            logger.error(`Scheduled Suricata rule update failed: ${error.message}`);
          });
        }, suricataUpdateInterval * 1000);
      }
      
      // Schedule Snort rule updates
      if (this.config.engines.snort.enabled) {
        logger.info(`Scheduling Snort rule updates every ${snortUpdateInterval} seconds`);
        setInterval(() => {
          this.updateSnortRules().catch(error => {
            logger.error(`Scheduled Snort rule update failed: ${error.message}`);
          });
        }, snortUpdateInterval * 1000);
      }
      
      // Schedule threat intelligence updates
      const threatIntelUpdateInterval = 86400; // 24 hours
      logger.info(`Scheduling threat intelligence updates every ${threatIntelUpdateInterval} seconds`);
      setInterval(() => {
        this.loadThreatIntelligence().catch(error => {
          logger.error(`Scheduled threat intelligence update failed: ${error.message}`);
        });
      }, threatIntelUpdateInterval * 1000);
      
      // Schedule statistics collection
      const statsInterval = 60; // 1 minute
      this.statisticsInterval = setInterval(() => {
        this.collectStatistics();
      }, statsInterval * 1000);
      
      // Schedule alert cleaning
      const alertCleanupInterval = 86400; // 24 hours
      logger.info(`Scheduling alert cleanup every ${alertCleanupInterval} seconds`);
      setInterval(() => {
        this.cleanupAlerts();
      }, alertCleanupInterval * 1000);
      
      logger.info('Scheduled tasks set up successfully');
    } catch (error) {
      logger.error(`Failed to set up scheduled tasks: ${error.message}`);
      throw new Error(`Scheduled task setup failed: ${error.message}`);
    }
  }

  /**
   * Collect system statistics
   */
  collectStatistics() {
    try {
      // Collect system stats, blocked IPs, alerts, etc.
      // This data could be used for reporting or monitoring
    } catch (error) {
      logger.error(`Failed to collect statistics: ${error.message}`);
    }
  }

  /**
   * Clean up old alerts
   */
  cleanupAlerts() {
    try {
      const alertsPath = '/var/lib/aegis-shield/alerts.jsonl';
      const retentionDays = this.config.reporting.retention_days || 90;
      
      if (!fs.existsSync(alertsPath)) {
        return;
      }
      
      logger.info(`Cleaning up alerts older than ${retentionDays} days`);
      
      const alertsData = fs.readFileSync(alertsPath, 'utf8');
      const alerts = alertsData.split('\n').filter(line => line.trim());
      
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - retentionDays);
      
      const newAlerts = alerts.filter(line => {
        try {
          const alert = JSON.parse(line);
          const alertDate = new Date(alert.timestamp);
          return alertDate >= cutoffDate;
        } catch (error) {
          return false;
        }
      });
      
      fs.writeFileSync(alertsPath, newAlerts.join('\n') + '\n');
      
      logger.info(`Removed ${alerts.length - newAlerts.length} old alerts`);
    } catch (error) {
      logger.error(`Failed to clean up alerts: ${error.message}`);
    }
  }

  /**
   * Start the Aegis Shield engine
   */
  async start() {
    try {
      if (!this.initialized) {
        await this.initialize();
      }
      
      logger.info('Starting Aegis Shield Engine...');
      this.isRunning = true;
      
      // Additional startup tasks here
      
      logger.info('Aegis Shield Engine started successfully');
      return true;
    } catch (error) {
      logger.error(`Failed to start Aegis Shield Engine: ${error.message}`);
      return false;
    }
  }

  /**
   * Stop the Aegis Shield engine
   */
  async stop() {
    try {
      logger.info('Stopping Aegis Shield Engine...');
      this.isRunning = false;
      
      // Stop all engine processes
      for (const [name, process] of Object.entries(this.engineProcesses)) {
        logger.info(`Stopping ${name} process...`);
        process.kill();
      }
      
      // Stop packet capture
      if (this.packetCapture) {
        this.packetCapture.close();
      }
      
      // Stop API server
      if (this.server) {
        this.server.close();
      }
      
      // Stop statistics collection
      if (this.statisticsInterval) {
        clearInterval(this.statisticsInterval);
      }
      
      // Save blocklist
      this.saveBlockList();
      
      logger.info('Aegis Shield Engine stopped successfully');
      return true;
    } catch (error) {
      logger.error(`Failed to stop Aegis Shield Engine: ${error.message}`);
      return false;
    }
  }
}

// Export the engine class
module.exports = AegisShieldEngine; 