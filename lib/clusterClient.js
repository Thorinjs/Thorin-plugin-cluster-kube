'use strict';
/**
 * This is our cluster client class.
 * */
const crypto = require('crypto'),
  DEFAULT_ALG = 'sha256',
  DEFAULT_PREFIX = 'D',
  DEFAULT_TIMEOUT = 60000;  // token expires in 1min

module.exports = function init(thorin, opt) {

  const ERROR_SERVICE = thorin.error('CLUSTER.DATA', 'Please provide the service name'),
    ERROR_ACTION = thorin.error('CLUSTER.DATA', 'Please provide the action name');

  const logger = thorin.logger(opt.logger),
    fetch = thorin.fetch;

  class ThorinClusterClient {

    #token = opt.token || null;

    /**
     * Manually override the ports of services
     * */
    setPorts(ports) {
      if (typeof ports === 'object' && ports && Object.keys(ports).length > 0) {
        if (typeof ports['_all'] === 'undefined' && typeof opt.port === 'object' && opt.port && opt.port._all) {
          ports['_all'] = opt.port._all;
        }
        opt.port = ports;
      }
    }

    getPorts() {
      return opt.port;
    }

    /**
     * Tries to perform a dispatch to a microservice, using nat's requestOne function.
     * @Arguments
     *  - service - the service name
     *  - action - the action name to call
     *  - payload - the payload to send
     *  - opt - (optional) the options
     *  - opt.timeout - specific timeout to use.
     *  - opt.required - if set to false, do not reject the promise if failed.
     *  Note:
     *    if opt is an intentObj, we will use its client() to sendout.
     * */
    async dispatch(service, action, payload = {}, _opt = {}) {
      if (typeof service !== 'string' || !service) throw ERROR_SERVICE;
      if (typeof action !== 'string' || !action) throw ERROR_ACTION;
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
        json: true,
        timeout: _opt.timeout || opt.timeout
      };
      if (this.#token) {
        fetchOpt.headers['x-cluster-token'] = this.sign(reqPayload, opt.service.id);
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
      if (opt.debug) {
        logger.trace(`dispatch -> [${service}#${action}]`, payload);
      }
      try {
        let r = await fetch(url, fetchOpt);
        if (r.type) delete r.type;
        logger.trace(`dispatch <- [${service}#${action}]`, r);
        return r;
      } catch (e) {
        if (opt.debug) {
          logger.trace(`dispatch <- [${service}#${action}]`, e.toJSON());
        }
        if (opt.required === false) return null;
        if (e.ns === 'FETCH') e.ns = 'CLUSTER';
        e.action = action;
        e.service = service;
        throw e;
      }
    }


    /**
     * Check if we have any kind of token for security
     * */
    hasToken() {
      return !!this.#token;
    }

    /**
     * Verifies the incoming HTTP Authorization header to see if it is an internal service or not.
     * Returns: {service data object}
     * */
    verifyToken(token, actionName) {
      if (!this.#token) return null;
      if (token.substr(0, DEFAULT_PREFIX.length) !== DEFAULT_PREFIX) return false;
      let publicData = token.split('$')[1],
        now = Date.now(),
        expireAt;
      if (typeof publicData !== 'string' || !publicData) return false;
      try {
        let tmp = Buffer.from(publicData, 'hex').toString('ascii');
        publicData = JSON.parse(tmp);
        expireAt = publicData.e;
        if (typeof expireAt !== 'number') throw 1;
        if (now >= expireAt) throw 1;  // expired.
      } catch (e) {
        return false;
      }
      // re-construct the hash and verify it.
      token = token.substr(DEFAULT_PREFIX.length).split('$')[0];
      let hashString = actionName + expireAt.toString();
      if (publicData.n) hashString += publicData.n;
      if (publicData.t) hashString += publicData.t;
      let hashValue = crypto.createHmac(DEFAULT_ALG, module.exports.TOKEN)
        .update(hashString)
        .digest('hex');
      let wrong = 0,
        max = Math.max(token.length, hashValue.length);
      for (let i = 0; i < max; i++) {
        if (token[i] !== hashValue[i]) wrong++;
      }
      if (wrong !== 0) return false;
      return publicData;
    }

    /**
     * Currently, when we "sign" the signature, we only
     * sha2 the actionName + ts + {service.name?optional} + {service.type?optional}
     * */
    sign(payload, service) {
      if (!this.#token) return null;
      if (!service) service = thorin.app;
      let expireAt = Date.now() + DEFAULT_TIMEOUT,
        hashString = payload.type + expireAt.toString();
      let publicData = {
        e: expireAt
      };
      if (service.name) {
        publicData.n = service.name;
        hashString += publicData.n;
      }
      if (service.type) {
        publicData.t = service.type;
        hashString += publicData.t;
      }

      publicData = JSON.stringify(publicData);
      let hashValue = crypto.createHmac(DEFAULT_ALG, this.#token)
        .update(hashString)
        .digest('hex');
      let publicStr = Buffer.from(publicData, 'ascii').toString('hex');
      return DEFAULT_PREFIX + hashValue + '$' + publicStr;
    }


  }

  return ThorinClusterClient;
}
