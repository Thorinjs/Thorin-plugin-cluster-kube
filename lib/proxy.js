'use strict';
/**
 * This creates an authorization middleware that will check that the incoming
 * request is made by a microservice within the cluster. We perform the check by checking
 * the access token as well as the user-agent
 */
module.exports = function (thorin, opt, pluginObj) {
  const logger = thorin.logger(opt.logger),
    dispatcher = thorin.dispatcher;


  /**
   * All you need to do in your actions is to add
   *   .authorization('cluster.proxy')
   * and all the incoming requests will be filtered by this.
   * OPTIONS:
   *  - required=true - if set to false, we will not stop request, but simply not set intentObj.data('proxy_auth', true)
   * */
  const ERROR_PROXY = thorin.error('CLUSTER.PROXY', 'Request not authorized.', 403);
  dispatcher
    .addAuthorization('cluster#proxy')
    .use((intentObj, next, opt) => {
      let clientData = intentObj.client(),
        tokenType = intentObj.authorizationSource,
        accessToken = intentObj.authorization;
      if (clientData.headers) {
        let headerToken = clientData.headers['x-cluster-token'];
        if (headerToken) {
          tokenType = 'TOKEN';
          accessToken = headerToken;
        }
      }
      // turned off
      if (!pluginObj.hasToken()) {
        intentObj.data('proxy_auth', true);
        intentObj._setAuthorization('CLUSTER', accessToken);
        return next();
      }
      if (tokenType !== 'TOKEN') {
        if (opt.required === false) {
          intentObj.data('proxy_auth', false);
          return next();
        }
        return next(ERROR_PROXY);
      }
      let serviceData = pluginObj.verifyToken(accessToken, intentObj.action);
      if (!serviceData) {
        logger.warn(`Received invalid proxy request for ${intentObj.action} from: ${clientData.ip}`);
        logger.warn(clientData, intentObj.rawInput);
        if (opt.required === false) {
          intentObj.data('proxy_auth', false);
          return next();
        }
        return next(ERROR_PROXY);
      }
      if (opt.required === false) {
        intentObj.data('proxy_auth', true);
        intentObj._setAuthorization('CLUSTER', accessToken);
      }
      intentObj.data('proxy_name', serviceData.n);
      if (serviceData.t) {
        intentObj.data('proxy_service', serviceData.t);
      }
      intentObj.resultHeaders('connection', 'keep-alive');
      next();
    });
}
