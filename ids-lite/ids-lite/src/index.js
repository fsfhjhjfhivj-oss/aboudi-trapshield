'use strict';
const { Ids } = require('./ids');
const { createMiddleware } = require('./middleware');
const { createRouter } = require('./api');
const { sign } = require('./crypto');

/**
 * createIds({ hmacKey | hmacKeys, ingestSecret, adminToken | adminAuth, dataDir, basePath })
 * returns the Ids instance with .middleware (enforcement + detection) and .router (REST API + static banner).
 */
function createIds(opts) {
  const ids = new Ids(opts);
  ids.middleware = createMiddleware(ids);
  Object.defineProperty(ids, 'router', { get() { return this._router || (this._router = createRouter(ids)); } });
  return ids.start();
}

/**
 * Pass to your GLOBAL body parser so signed endpoints can verify the exact bytes that were signed:
 *   app.use(express.json({ verify: rawBodySaver }));
 */
const rawBodySaver = (req, _res, buf) => { req.rawBody = buf.toString('utf8'); };

module.exports = { createIds, Ids, sign, rawBodySaver };
