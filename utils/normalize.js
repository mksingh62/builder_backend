// Helper to normalize MongoDB _id to id in responses
function normalizeDoc(doc) {
  if (!doc) return doc;
  if (doc.toObject) {
    const obj = doc.toObject();
    if (obj._id) {
      obj.id = obj._id.toString();
      delete obj._id;
    }
    return obj;
  }
  if (doc._id) {
    doc.id = doc._id.toString();
    delete doc._id;
  }
  return doc;
}

function normalizeArray(docs) {
  if (!Array.isArray(docs)) return docs;
  return docs.map(normalizeDoc);
}

module.exports = { normalizeDoc, normalizeArray };
