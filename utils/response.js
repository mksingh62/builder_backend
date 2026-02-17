function success(res, data, statusCode = 200) {
  return res.status(statusCode).json({ success: true, ...(data && (typeof data === 'object' && !Array.isArray(data) ? data : { data })) });
}

function created(res, data) {
  return success(res, data, 201);
}

function noContent(res) {
  return res.status(204).send();
}

function error(res, message, statusCode = 400) {
  return res.status(statusCode).json({ success: false, message });
}

module.exports = { success, created, noContent, error };
