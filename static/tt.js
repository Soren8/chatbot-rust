(function (global) {
  'use strict';
  if (typeof trustedTypes === 'undefined' || !trustedTypes.createPolicy) {
    return;
  }
  // Identity default so jquery / bootstrap / highlight.js can assign HTML.
  // First-party sinks should use window.__chatbotTt (policy name `chatbot`).
  trustedTypes.createPolicy('default', {
    createHTML: function (s) { return s; },
  });
  global.__chatbotTt = trustedTypes.createPolicy('chatbot', {
    createHTML: function (s) { return s; },
  });
})(window);
