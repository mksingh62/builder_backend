// Simple structured logger (can be replaced with winston/pino later)
const config = require('../config');

const logLevels = {
  ERROR: 0,
  WARN: 1,
  INFO: 2,
  DEBUG: 3,
};

const currentLevel = config.nodeEnv === 'production' ? logLevels.INFO : logLevels.DEBUG;

function log(level, message, meta = {}) {
  if (logLevels[level] <= currentLevel) {
    const timestamp = new Date().toISOString();
    const logEntry = {
      timestamp,
      level,
      message,
      ...meta,
    };
    console.log(JSON.stringify(logEntry));
  }
}

const logger = {
  error: (message, meta) => log('ERROR', message, meta),
  warn: (message, meta) => log('WARN', message, meta),
  info: (message, meta) => log('INFO', message, meta),
  debug: (message, meta) => log('DEBUG', message, meta),
};

module.exports = logger;
