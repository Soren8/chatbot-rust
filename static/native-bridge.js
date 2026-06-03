(function (global) {
  'use strict';

  const pluginCache = {};

  function isNativePlatform() {
    return !!(
      global.Capacitor &&
      typeof global.Capacitor.isNativePlatform === 'function' &&
      global.Capacitor.isNativePlatform()
    );
  }

  function getPlugin(pluginName) {
    if (pluginCache[pluginName]) {
      return pluginCache[pluginName];
    }
    const cap = global.Capacitor;
    if (!cap) {
      return null;
    }
    if (typeof cap.registerPlugin === 'function') {
      pluginCache[pluginName] = cap.registerPlugin(pluginName);
      return pluginCache[pluginName];
    }
    if (cap.Plugins && cap.Plugins[pluginName]) {
      pluginCache[pluginName] = cap.Plugins[pluginName];
      return pluginCache[pluginName];
    }
    return null;
  }

  function callNativePlugin(pluginName, methodName, options) {
    if (!isNativePlatform()) {
      return Promise.reject(new Error('Not a native platform'));
    }
    const plugin = getPlugin(pluginName);
    if (plugin && typeof plugin[methodName] === 'function') {
      return plugin[methodName](options || {});
    }
    const cap = global.Capacitor;
    if (cap && typeof cap.nativePromise === 'function') {
      return cap.nativePromise(pluginName, methodName, options || {});
    }
    return Promise.reject(new Error('Native bridge unavailable for ' + pluginName + '.' + methodName));
  }

  global.NativeBridge = {
    isNativePlatform,
    getPlugin,
    callNativePlugin,
  };
})(window);
