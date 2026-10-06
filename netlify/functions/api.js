const serverless = require('serverless-http');
const app = require('../../server.js');
const handler = serverless(app, { binary: ['image/*'] });

exports.handler = (event, context) => {
  let p = String(event.path || '').replace(/^\/\.netlify\/functions\/api/, '');
  if (!p.startsWith('/api')) p = '/api' + p;
  event.path = p;
  return handler(event, context);
};
