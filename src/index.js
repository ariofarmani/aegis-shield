/**
 * Aegis Shield - Military-Grade IDS/IPS
 * ================================================
 * Main entry point that initializes and runs the Aegis Shield engine
 */

'use strict';

// Import the Aegis Shield engine
const AegisShieldEngine = require('./aegis-shield-engine');

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error(`FATAL ERROR: Uncaught exception: ${error.message}`, error);
  process.exit(1);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error('FATAL ERROR: Unhandled Promise rejection', reason);
  process.exit(1);
});

/**
 * Main function to start the Aegis Shield engine
 */
async function main() {
  console.log('========================================================');
  console.log('     AEGIS SHIELD - MILITARY-GRADE IDS/IPS SYSTEM       ');
  console.log('========================================================');
  console.log('Starting Aegis Shield...');
  
  // Check if running as root
  if (process.getuid && process.getuid() !== 0) {
    console.error('ERROR: Aegis Shield must be run as root');
    process.exit(1);
  }
  
  // Create and initialize the engine
  const aegisShield = new AegisShieldEngine();
  
  // Register signal handlers
  process.on('SIGINT', async () => {
    console.log('\nReceived SIGINT. Shutting down...');
    await aegisShield.stop();
    process.exit(0);
  });
  
  process.on('SIGTERM', async () => {
    console.log('Received SIGTERM. Shutting down...');
    await aegisShield.stop();
    process.exit(0);
  });
  
  // Start the engine
  try {
    const success = await aegisShield.start();
    
    if (!success) {
      console.error('Failed to start Aegis Shield');
      process.exit(1);
    }
    
    console.log('========================================================');
    console.log('     AEGIS SHIELD IS NOW PROTECTING YOUR NETWORK        ');
    console.log('========================================================');
  } catch (error) {
    console.error(`Failed to start Aegis Shield: ${error.message}`, error);
    process.exit(1);
  }
}

// Run the main function
main().catch((error) => {
  console.error(`FATAL ERROR: ${error.message}`, error);
  process.exit(1);
}); 