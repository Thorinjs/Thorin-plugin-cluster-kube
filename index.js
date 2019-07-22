'use strict';

const initClient = require('./lib/client');

/**
 * Cluster plugin for microservice communication within a kube cluster
 */
module.exports = function (thorin, opt, pluginName) {
  opt = thorin.util.extend({
    logger: pluginName || 'cluster',
    service: {
      type: thorin.app,
      name: thorin.id
    },       // this is the service name
    token: process.env.CLUSTER_TOKEN || null, // A shared verification token used for auth
    namespace: 'svc.cluster.local',         // The kube namespace name
    protocol: 'http',               // The default protocol for all communication
    port: {
      _all: 8080              // A map with {serviceName:port} for any registered services.
    },                             // The default microservice port
    path: '/',                       // The default microservice dispatch path
    timeout: 40000                  // The max timeout to use.
  }, opt);
  const logger = thorin.logger(opt.logger),
    pluginObj = {};
  if (!opt.token) {
    logger.warn(`cluster-kube: working without service authentication (no token present)`);
  }

  /* Manually override the ports of services */
  pluginObj.setPorts = (ports) => {
    if (typeof ports === 'object' && ports && Object.keys(ports).length > 0) {
      if (typeof ports['_all'] === 'undefined' && typeof opt.port === 'object' && opt.port && opt.port._all) {
        ports['_all'] = opt.port._all;
      }
      opt.port = ports;
    }
  };
  pluginObj.getPorts = () => {
    return opt.port;
  };

  initClient(thorin, opt, pluginObj);
  return pluginObj;
};
module.exports.publicName = 'cluster';