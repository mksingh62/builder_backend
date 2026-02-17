const config = require('../config');

function errorHandler(err, req, res, next) {
  const isProd = config.nodeEnv === 'production';

  if (err.name === 'ValidationError') {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: Object.values(err.errors).map(e => e.message),
    });
  }

  if (err.code === 11000) {
    return res.status(409).json({
      success: false,
      message: 'Duplicate value',
      field: Object.keys(err.keyPattern || {})[0],
    });
  }

  const status = err.statusCode || 500;
  const message = status === 500 && isProd ? 'Internal server error' : (err.message || 'Something went wrong');

  if (status === 500) {
    console.error('Error:', err.message);
    if (!isProd && err.stack) console.error(err.stack);
  }

  res.status(status).json({
    success: false,
    message,
    ...(err.errors && { errors: err.errors }),
  });
}

module.exports = errorHandler;
