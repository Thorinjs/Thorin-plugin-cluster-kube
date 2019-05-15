'use strict';
/**
 * This is the client dispatcher, that uses thorin's fetch internally.
 * */
const security = require('./security'),
  initProxy = require('./proxy');
module.exports = (thorin, opt, pluginObj) => {
  const logger = thorin.logger(opt),
    fetch = thorin.fetch;
  initProxy(thorin, opt, pluginObj);
  if (opt.token) security.TOKEN = opt.token;
  /**
   * Tries to perform a dispatch to a microservice, using nat's requestOne function.
   * @Arguments
   *  - service - the service name
   *  - action - the action name to call
   *  - payload - the payload to send
   *  - opt - (optional) the options
   *  - opt.timeout - specific timeout to use.
   *  - opt.requierd - if set to false, do not reject the promise if failed.
   *  Note:
   *    if opt is an intentObj, we will use its client() to sendout.
   * */
  pluginObj.dispatch = (service, action, payload = {}, _opt = {}) => {
    if (typeof service !== 'string' || !service) throw thorin.error('CLUSTER.DATA', 'Please provide the service name');
    if (typeof action !== 'string' || !action) throw thorin.error('CLUSTER.DATA', 'Please provide the action name');
    if (typeof payload !== 'object' || !payload) payload = {};
    let reqPayload = {
      type: action,
      payload: payload || {}
    };
    let fetchOpt = {
      body: '',
      method: 'POST',
      follow: 1,
      headers: {
        'content-type': 'application/json',
        'connection': 'keep-alive',
        'x-cluster-kube': 'true'
      },
      timeout: _opt.timeout || opt.timeout
    };
    if (opt.token) {
      fetchOpt.headers['x-cluster-token'] = pluginObj.sign(reqPayload, opt.service.id);
    }
    let url = `${opt.protocol}://${service}`;
    if (opt.namespace) url += `.${opt.namespace}`;
    let port = (typeof opt.port === 'number') ? opt.port : null;
    if (!port && typeof opt.port === 'object' && opt.port) {
      port = opt.port[service] || opt.port['_all'];
    }
    if (port) {
      url += `:${port}`;
    }
    url += `${opt.path}`;
    try {
      fetchOpt.body = JSON.stringify(reqPayload);
    } catch (e) {
    }
    return new Promise((resolve, reject) => {
      let statusCode;
      fetch(url, fetchOpt)
        .then(function (res) {
          statusCode = res.status;
          return res.json();
        })
        .then(function (resultData) {
          if (statusCode >= 200 && statusCode <= 299) {
            if (resultData.type) {
              delete resultData.type;
            }
            return resolve(resultData);
          }
          if (_opt.required === false) {
            return resolve(null);
          }
          let errData = resultData.error || {},
            msg = errData.message || 'Failed to execute fetch',
            status = errData.status || 400,
            code = (errData.code || 'FETCH.ERROR');
          msg = msg + ` (${action})`;
          let err = thorin.error(code, msg, status);
          err.ns = errData.ns || 'FETCH';
          if (!err.data) err.data = {};
          err.data.action = action;
          reject(err);
        })
        .catch(function (e) {
          if (e.ns) return reject(e);  // already constructed.
          if (e && e.ns === 'FETCH') {
            if (_opt.required === false) return resolve(null);
            if (e.message) e.message += ` (${action})`;
            return reject(e);
          }
          let msg = '',
            status = 400,
            code = 'FETCH.';
          if (e) {
            if (e instanceof SyntaxError) {
              code += 'RESPONSE';
              msg = 'Request data could not be processed.';
            } else {
              switch (e.type) {
                case 'request-timeout':
                  code += 'TIMEOUT';
                  msg = 'Request timed out';
                  break;
                default:
                  code += 'ERROR';
                  msg = 'Could not contact the server';
                  status = statusCode || 400;
              }
            }
          }
          let tErr = thorin.error(code, msg, status, e);
          if (!tErr.data) tErr.data = {};
          tErr.data.action = action;
          if (_opt.required === false) {
            resolve(null);
          }
          return reject(tErr);
        });
    });
  }

};
