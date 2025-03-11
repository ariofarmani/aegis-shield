/**
 * Aegis Shield - Advanced Security Dashboard
 * Military-grade visualization and monitoring system
 */

const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const fs = require('fs');
const yaml = require('js-yaml');
const moment = require('moment');
const os = require('os');
const { exec } = require('child_process');

// Dashboard application
class AegisShieldDashboard {
  constructor(config) {
    this.config = config;
    this.app = express();
    this.server = http.createServer(this.app);
    this.io = socketIo(this.server);
    this.connectionData = new Map();
    this.alertHistory = [];
    this.threatMap = new Map();
    this.loadedConfig = null;
    
    // Statistics tracking
    this.stats = {
      blockedConnections: 0,
      totalTrafficGB: 0,
      attacksDetected: 0,
      activeConnections: 0,
      alertsTriggered: 0,
      systemHealth: 100,
      lastUpdated: Date.now()
    };
    
    this.initialize();
  }

  /**
   * Initialize the dashboard application
   */
  initialize() {
    console.log('Initializing Aegis Shield Dashboard...');
    
    // Configure Express application
    this.configureExpress();
    
    // Set up routes
    this.setupRoutes();
    
    // Configure WebSocket for real-time updates
    this.configureWebSocket();
    
    // Start monitoring system resources
    this.startResourceMonitoring();
    
    // Start log monitoring
    this.startLogMonitoring();
    
    // Start network monitoring
    this.startNetworkMonitoring();
    
    console.log('Aegis Shield Dashboard initialized successfully');
  }

  /**
   * Configure Express middleware and settings
   */
  configureExpress() {
    // Set up static file serving
    this.app.use(express.static(path.join(__dirname, 'public')));
    
    // Body parser for API requests
    this.app.use(express.json());
    
    // Set view engine
    this.app.set('view engine', 'ejs');
    this.app.set('views', path.join(__dirname, 'views'));
    
    // Security headers
    this.app.use((req, res, next) => {
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('X-Frame-Options', 'DENY');
      res.setHeader('X-XSS-Protection', '1; mode=block');
      res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:;");
      next();
    });
  }

  /**
   * Set up application routes
   */
  setupRoutes() {
    // Main dashboard
    this.app.get('/', (req, res) => {
      res.render('dashboard', {
        title: 'Aegis Shield Command Center',
        version: this.config.version || '1.0.0'
      });
    });
    
    // Log monitoring page
    this.app.get('/logs', (req, res) => {
      res.render('logs', {
        title: 'Security Logs | Aegis Shield',
        version: this.config.version || '1.0.0'
      });
    });
    
    // Network monitoring page
    this.app.get('/network', (req, res) => {
      res.render('network', {
        title: 'Network Monitoring | Aegis Shield',
        version: this.config.version || '1.0.0'
      });
    });
    
    // Threats page
    this.app.get('/threats', (req, res) => {
      res.render('threats', {
        title: 'Threat Intelligence | Aegis Shield',
        version: this.config.version || '1.0.0'
      });
    });
    
    // Configuration page
    this.app.get('/config', (req, res) => {
      res.render('config', {
        title: 'System Configuration | Aegis Shield',
        version: this.config.version || '1.0.0',
        config: this.loadedConfig || {}
      });
    });
    
    // API endpoints
    this.app.get('/api/status', (req, res) => {
      res.json({
        status: 'operational',
        uptime: process.uptime(),
        timestamp: Date.now(),
        stats: this.stats
      });
    });
    
    this.app.get('/api/alerts', (req, res) => {
      res.json({
        alerts: this.alertHistory.slice(-100) // Return last 100 alerts
      });
    });
    
    this.app.get('/api/network', (req, res) => {
      res.json({
        connections: Array.from(this.connectionData.values()).slice(-1000)
      });
    });
    
    this.app.post('/api/block', (req, res) => {
      const { ip, reason } = req.body;
      
      if (!ip) {
        return res.status(400).json({ error: 'IP address is required' });
      }
      
      this.blockIP(ip, reason || 'Manual block via dashboard')
        .then(() => {
          res.json({ success: true, message: `Blocked IP: ${ip}` });
        })
        .catch(error => {
          res.status(500).json({ error: error.message });
        });
    });
    
    // Error handler
    this.app.use((err, req, res, next) => {
      console.error('Error in dashboard request:', err);
      res.status(500).render('error', {
        title: 'Error | Aegis Shield',
        error: err.message
      });
    });
  }

  /**
   * Configure WebSocket for real-time updates
   */
  configureWebSocket() {
    this.io.on('connection', (socket) => {
      console.log('New dashboard client connected');
      
      // Send initial data
      socket.emit('stats', this.stats);
      socket.emit('alerts', this.alertHistory.slice(-50));
      
      // Handle client requests
      socket.on('requestNetworkData', () => {
        socket.emit('networkData', Array.from(this.connectionData.values()).slice(-1000));
      });
      
      socket.on('requestThreatMap', () => {
        socket.emit('threatMap', Array.from(this.threatMap.entries()));
      });
      
      socket.on('disconnect', () => {
        console.log('Dashboard client disconnected');
      });
    });
    
    // Set up periodic updates
    setInterval(() => {
      this.io.emit('stats', this.stats);
    }, 1000);
    
    setInterval(() => {
      this.io.emit('networkUpdate', Array.from(this.connectionData.values()).slice(-20));
    }, 2000);
  }

  /**
   * Start monitoring system resources
   */
  startResourceMonitoring() {
    setInterval(() => {
      const cpuUsage = os.loadavg()[0] / os.cpus().length;
      const memoryUsage = 1 - (os.freemem() / os.totalmem());
      
      // Update system health based on resource usage
      const cpuHealth = 100 - (cpuUsage * 100);
      const memoryHealth = 100 - (memoryUsage * 100);
      this.stats.systemHealth = Math.min(cpuHealth, memoryHealth);
      this.stats.lastUpdated = Date.now();
      
      // Check if system is under stress
      if (cpuUsage > 0.8 || memoryUsage > 0.9) {
        this.addAlert({
          level: 'warning',
          title: 'System Resources Critical',
          message: `High resource usage: CPU ${(cpuUsage * 100).toFixed(1)}%, Memory ${(memoryUsage * 100).toFixed(1)}%`,
          timestamp: Date.now()
        });
      }
    }, 5000);
  }

  /**
   * Start monitoring security logs
   */
  startLogMonitoring() {
    // Simulated log paths - these would be real paths in production
    const logPaths = [
      '/var/log/aegis-shield/security.log',
      '/var/log/aegis-shield/network.log',
      '/var/log/aegis-shield/engine.log'
    ];
    
    // Monitor each log file
    logPaths.forEach(logPath => {
      try {
        if (fs.existsSync(logPath)) {
          this.monitorLogFile(logPath);
        }
      } catch (error) {
        console.error(`Error monitoring log file ${logPath}:`, error);
      }
    });
    
    // Simulate log entries for demonstration
    this.simulateLogEntries();
  }

  /**
   * Monitor a specific log file for changes
   */
  monitorLogFile(filePath) {
    let lastSize = 0;
    
    try {
      const stats = fs.statSync(filePath);
      lastSize = stats.size;
    } catch (error) {
      console.error(`Error getting file stats for ${filePath}:`, error);
      return;
    }
    
    // Check for file changes periodically
    setInterval(() => {
      try {
        const stats = fs.statSync(filePath);
        
        if (stats.size > lastSize) {
          // File has grown, read new data
          const fileStream = fs.createReadStream(filePath, {
            start: lastSize,
            end: stats.size
          });
          
          let newData = '';
          
          fileStream.on('data', (chunk) => {
            newData += chunk.toString();
          });
          
          fileStream.on('end', () => {
            this.processLogData(filePath, newData);
            lastSize = stats.size;
          });
        }
      } catch (error) {
        console.error(`Error monitoring log file ${filePath}:`, error);
      }
    }, 1000);
  }

  /**
   * Process new log data
   */
  processLogData(source, data) {
    const lines = data.split('\n').filter(line => line.trim());
    
    lines.forEach(line => {
      // Parse log line based on format
      let logEntry;
      
      try {
        // Attempt to parse as JSON
        logEntry = JSON.parse(line);
      } catch (e) {
        // Parse as plain text with timestamp
        const match = line.match(/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?) (.+?)(?:: (.*))?$/);
        
        if (match) {
          logEntry = {
            timestamp: new Date(match[1]).getTime(),
            level: match[2].toLowerCase(),
            message: match[3] || match[2]
          };
        } else {
          // Fallback parsing
          logEntry = {
            timestamp: Date.now(),
            level: line.includes('ERROR') ? 'error' : 
                   line.includes('WARN') ? 'warning' : 'info',
            message: line
          };
        }
      }
      
      // Process based on log level
      if (logEntry.level === 'error' || logEntry.level === 'warning') {
        this.addAlert({
          level: logEntry.level,
          source: source.split('/').pop(),
          title: `Log ${logEntry.level.toUpperCase()}`,
          message: logEntry.message,
          timestamp: logEntry.timestamp || Date.now()
        });
      }
      
      // Emit to connected clients
      this.io.emit('logEntry', {
        source: source.split('/').pop(),
        entry: logEntry
      });
    });
  }

  /**
   * Simulate log entries for demonstration purposes
   */
  simulateLogEntries() {
    const logTypes = [
      { level: 'info', weight: 70 },
      { level: 'warning', weight: 20 },
      { level: 'error', weight: 10 }
    ];
    
    const logMessages = {
      info: [
        'User authentication successful',
        'Configuration updated',
        'Security scan completed',
        'Network scan finished',
        'Service started successfully',
        'Update check completed',
        'Connection established with remote endpoint',
        'Firewall rule applied successfully',
        'Database integrity check passed',
        'Certificate validation successful'
      ],
      warning: [
        'Multiple authentication failures detected',
        'Unusual traffic pattern detected',
        'Service response time degraded',
        'Potential port scan detected',
        'Memory usage approaching threshold',
        'Database query performance degraded',
        'Certificate expiration approaching',
        'Unusual login time detected',
        'Multiple connection attempts from same source',
        'Configuration drift detected'
      ],
      error: [
        'Authentication failure',
        'Service failed to start',
        'Database connection lost',
        'Certificate validation failed',
        'Firewall rule application failed',
        'Security scan failed',
        'Connection timeout with remote endpoint',
        'Data integrity check failed',
        'Critical service unavailable',
        'Update installation failed'
      ]
    };
    
    // Generate random log entries periodically
    setInterval(() => {
      // Weighted random selection of log level
      const totalWeight = logTypes.reduce((acc, type) => acc + type.weight, 0);
      let random = Math.random() * totalWeight;
      
      const selectedLevel = logTypes.find(type => {
        random -= type.weight;
        return random <= 0;
      }).level;
      
      // Select random message for level
      const messages = logMessages[selectedLevel];
      const message = messages[Math.floor(Math.random() * messages.length)];
      
      // Create log entry
      const timestamp = Date.now();
      const logEntry = {
        timestamp,
        level: selectedLevel,
        message
      };
      
      // Process as if it came from a log file
      if (selectedLevel === 'error' || selectedLevel === 'warning') {
        this.addAlert({
          level: selectedLevel,
          source: 'simulated',
          title: `${selectedLevel.toUpperCase()}: ${message.split(' ').slice(0, 3).join(' ')}...`,
          message,
          timestamp
        });
      }
      
      // Emit to connected clients
      this.io.emit('logEntry', {
        source: 'simulated.log',
        entry: logEntry
      });
      
    }, 5000); // Generate a log every 5 seconds
  }

  /**
   * Start monitoring network connections
   */
  startNetworkMonitoring() {
    // Simulate network data for demonstration
    this.simulateNetworkTraffic();
    
    // In a real implementation, this would use pcap or another network monitoring library
    // to capture and analyze actual network traffic
  }

  /**
   * Simulate network traffic for demonstration
   */
  simulateNetworkTraffic() {
    const protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'ICMP'];
    const countries = ['US', 'CN', 'RU', 'GB', 'DE', 'FR', 'JP', 'BR', 'IN', 'KR'];
    const localIPs = ['192.168.1.10', '192.168.1.11', '192.168.1.12', '10.0.0.5', '10.0.0.6'];
    const ports = [80, 443, 22, 53, 25, 3389, 8080, 8443];
    
    // Generate remote IPs for different countries
    const remoteIPs = {};
    countries.forEach(country => {
      remoteIPs[country] = Array.from({ length: 10 }, (_, i) => {
        const octet1 = Math.floor(Math.random() * 223) + 1;
        const octet2 = Math.floor(Math.random() * 256);
        const octet3 = Math.floor(Math.random() * 256);
        const octet4 = Math.floor(Math.random() * 254) + 1;
        return `${octet1}.${octet2}.${octet3}.${octet4}`;
      });
    });
    
    // Generate connection data periodically
    setInterval(() => {
      const timestamp = Date.now();
      const protocol = protocols[Math.floor(Math.random() * protocols.length)];
      const country = countries[Math.floor(Math.random() * countries.length)];
      const remoteIP = remoteIPs[country][Math.floor(Math.random() * remoteIPs[country].length)];
      const localIP = localIPs[Math.floor(Math.random() * localIPs.length)];
      const remotePort = ports[Math.floor(Math.random() * ports.length)];
      const localPort = 1024 + Math.floor(Math.random() * 64511);
      const bytesIn = Math.floor(Math.random() * 10000);
      const bytesOut = Math.floor(Math.random() * 10000);
      
      // Randomly determine if connection is suspicious
      const isSuspicious = Math.random() < 0.1; // 10% chance
      const isMalicious = isSuspicious && Math.random() < 0.3; // 30% of suspicious are malicious
      
      // Generate connection data
      const connection = {
        id: `${timestamp}-${localIP}-${remoteIP}`,
        timestamp,
        protocol,
        localIP,
        localPort,
        remoteIP,
        remotePort,
        remoteCountry: country,
        bytesIn,
        bytesOut,
        state: isMalicious ? 'blocked' : (isSuspicious ? 'suspicious' : 'established'),
        duration: 0,
        flags: protocol === 'TCP' ? ['ACK', 'PSH'].join(' ') : '',
        isSuspicious,
        isMalicious,
        reason: isMalicious ? 'Malicious pattern detected' : (isSuspicious ? 'Suspicious behavior' : '')
      };
      
      // Store connection
      this.connectionData.set(connection.id, connection);
      
      // Limit stored connections
      if (this.connectionData.size > 10000) {
        // Remove oldest entries
        const entriesToRemove = this.connectionData.size - 10000;
        const entries = Array.from(this.connectionData.entries());
        for (let i = 0; i < entriesToRemove; i++) {
          this.connectionData.delete(entries[i][0]);
        }
      }
      
      // Update statistics
      this.stats.totalTrafficGB += (bytesIn + bytesOut) / (1024 * 1024 * 1024);
      this.stats.activeConnections = this.connectionData.size;
      
      // Handle suspicious/malicious connections
      if (isSuspicious) {
        this.stats.alertsTriggered++;
        
        if (isMalicious) {
          this.stats.attacksDetected++;
          this.stats.blockedConnections++;
          
          this.addAlert({
            level: 'error',
            title: 'Malicious Connection Blocked',
            message: `Blocked connection from ${remoteIP} (${country}) to ${localIP}:${localPort} using ${protocol}`,
            timestamp
          });
          
          // Update threat map
          const threatKey = `${country}:${remoteIP}`;
          if (this.threatMap.has(threatKey)) {
            const threatData = this.threatMap.get(threatKey);
            threatData.count++;
            threatData.lastSeen = timestamp;
            this.threatMap.set(threatKey, threatData);
          } else {
            this.threatMap.set(threatKey, {
              ip: remoteIP,
              country,
              count: 1,
              firstSeen: timestamp,
              lastSeen: timestamp
            });
          }
        } else {
          this.addAlert({
            level: 'warning',
            title: 'Suspicious Connection',
            message: `Detected suspicious connection from ${remoteIP} (${country}) to ${localIP}:${localPort} using ${protocol}`,
            timestamp
          });
        }
      }
      
      // Emit to connected clients
      this.io.emit('connectionUpdate', connection);
    }, 1000); // Generate a connection every second
    
    // Simulate connection closures
    setInterval(() => {
      // Update durations and close some connections
      for (const [id, connection] of this.connectionData.entries()) {
        // Update duration
        connection.duration = (Date.now() - connection.timestamp) / 1000;
        
        // 10% chance to close connection if it's been open for more than 30 seconds
        if (connection.duration > 30 && Math.random() < 0.1) {
          connection.state = 'closed';
          
          // Emit closure event
          this.io.emit('connectionClosed', { id });
          
          // Remove from connection data
          this.connectionData.delete(id);
        }
      }
      
      // Update active connections count
      this.stats.activeConnections = Array.from(this.connectionData.values())
        .filter(c => c.state !== 'closed').length;
        
    }, 10000); // Check every 10 seconds
  }

  /**
   * Add an alert to the history
   */
  addAlert(alert) {
    this.alertHistory.push(alert);
    
    // Limit alert history size
    if (this.alertHistory.length > 1000) {
      this.alertHistory.shift();
    }
    
    // Emit to connected clients
    this.io.emit('alert', alert);
  }

  /**
   * Block an IP address
   */
  async blockIP(ip, reason) {
    console.log(`Blocking IP ${ip}: ${reason}`);
    
    // In production, this would call the actual firewall integration module
    // For this demo, we'll just simulate the blocking
    
    // Add to statistics
    this.stats.blockedConnections++;
    
    // Add alert
    this.addAlert({
      level: 'info',
      title: 'IP Address Blocked',
      message: `Blocked IP address ${ip}: ${reason}`,
      timestamp: Date.now()
    });
    
    return Promise.resolve();
  }

  /**
   * Load configuration from file
   */
  loadConfiguration() {
    try {
      const configPath = this.config.configPath || '/etc/aegis-shield/config.yaml';
      if (fs.existsSync(configPath)) {
        const configFile = fs.readFileSync(configPath, 'utf8');
        this.loadedConfig = yaml.load(configFile);
        console.log('Configuration loaded successfully');
      } else {
        console.warn(`Configuration file not found at ${configPath}`);
      }
    } catch (error) {
      console.error('Error loading configuration:', error);
    }
  }

  /**
   * Start the dashboard server
   */
  start(port = 8443) {
    return new Promise((resolve, reject) => {
      try {
        this.server.listen(port, () => {
          console.log(`Aegis Shield Dashboard running on port ${port}`);
          resolve(port);
        });
      } catch (error) {
        console.error('Failed to start dashboard server:', error);
        reject(error);
      }
    });
  }

  /**
   * Stop the dashboard server
   */
  stop() {
    return new Promise((resolve, reject) => {
      try {
        this.server.close(() => {
          console.log('Aegis Shield Dashboard stopped');
          resolve();
        });
      } catch (error) {
        console.error('Error stopping dashboard server:', error);
        reject(error);
      }
    });
  }
}

// Export the dashboard class
module.exports = AegisShieldDashboard; 