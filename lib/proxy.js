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
      try {
        pluginObj.authorizeIntent(intentObj, opt);
        next();
      } catch (e) {
        next(e);
      }
    });
}
