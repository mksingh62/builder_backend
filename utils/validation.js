// Simple validation helpers
function validatePhone(phone) {
  if (!phone || typeof phone !== 'string') return false;
  const cleaned = phone.replace(/\D/g, '');
  return cleaned.length >= 10 && cleaned.length <= 15;
}

function validatePassword(password) {
  if (!password || typeof password !== 'string') return false;
  return password.length >= 6;
}

function validateEmail(email) {
  if (!email || typeof email !== 'string') return false;
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email);
}

function validateRequired(value, fieldName) {
  if (value === null || value === undefined || value === '') {
    return { valid: false, message: `${fieldName} is required` };
  }
  return { valid: true };
}

function validateNumber(value, fieldName, min = null, max = null) {
  const num = Number(value);
  if (isNaN(num)) {
    return { valid: false, message: `${fieldName} must be a number` };
  }
  if (min !== null && num < min) {
    return { valid: false, message: `${fieldName} must be at least ${min}` };
  }
  if (max !== null && num > max) {
    return { valid: false, message: `${fieldName} must be at most ${max}` };
  }
  return { valid: true, value: num };
}

module.exports = {
  validatePhone,
  validatePassword,
  validateEmail,
  validateRequired,
  validateNumber,
};
