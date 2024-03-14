'use strict';

const initClient = require('./lib/clusterClient'),
  initProxy = require('./lib/proxy');

/**
 * Cluster plugin for microservice communication within a kube cluster
 */
module.exports = function init(thorin, opt, pluginName) {
  opt = thorin.util.extend({
    logger: pluginName || 'cluster',
    debug: false,
    service: {
      type: thorin.app,
      name: thorin.id
    },       // this is the service name
    token: process.env.CLUSTER_TOKEN || null, // A shared verification token used for auth
    tokenHeader: 'x-cluster-token',         // The HTTP header to place the auth token in
    namespace: 'svc.cluster.local',         // The kube namespace name
    protocol: 'http',               // The default protocol for all communication
    alias: {  // aliases for services.
    },
    port: {
      _all: 8080              // A map with {serviceName:port} for any registered services.
    },                             // The default microservice port
    path: '/',                       // The default microservice dispatch path
    timeout: 20000                  // The max timeout to use.
  }, opt);
  const logger = thorin.logger(opt.logger),
    ClusterClient = initClient(thorin, opt);
  if (!opt.token) {
    logger.warn(`Thorin-cluster-kube: working without service authentication (no token present)`);
  }
  let pluginObj = new ClusterClient();
  initProxy(thorin, opt, pluginObj);

  return pluginObj;
};
module.exports.publicName = 'cluster';
