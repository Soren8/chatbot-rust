(function (root, factory) {
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = factory();
  } else {
    root.ChatStreamDecoder = factory();
  }
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  // Stream wire decoder: <think>...</think> (or ...[BEGIN FINAL RESPONSE])
  // carries reasoning/status text; [ConsoleError]...[/ConsoleError] carries
  // console detail. Callers own DOM/status accumulation and rendering. Chat
  // strips console detail and flushes at EOF/interrupt; regenerate and
  // history do not.

  var OPEN_TAG = '<think>';
  var CLOSE_TAGS = ['</think>', '[BEGIN FINAL RESPONSE]'];
  var CONSOLE_OPEN = '[ConsoleError]';
  var CONSOLE_CLOSE = '[/ConsoleError]';

  function findEarliestClose(buffer) {
    var firstIdx = -1;
    var usedLen = 0;
    for (var i = 0; i < CLOSE_TAGS.length; i++) {
      var idx = buffer.indexOf(CLOSE_TAGS[i]);
      if (idx !== -1 && (firstIdx === -1 || idx < firstIdx)) {
        firstIdx = idx;
        usedLen = CLOSE_TAGS[i].length;
      }
    }
    if (firstIdx === -1) return null;
    return { index: firstIdx, length: usedLen };
  }

  function visibleFlushEnd(buffer) {
    var flushableEnd = buffer.length;
    for (var i = 1; i <= buffer.length && i <= OPEN_TAG.length; i++) {
      var suffix = buffer.substring(buffer.length - i);
      if (OPEN_TAG.indexOf(suffix) === 0) {
        flushableEnd = buffer.length - i;
        break;
      }
    }
    return flushableEnd;
  }

  function thinkingFlushEnd(buffer) {
    var maxTagLen = 0;
    for (var i = 0; i < CLOSE_TAGS.length; i++) {
      if (CLOSE_TAGS[i].length > maxTagLen) maxTagLen = CLOSE_TAGS[i].length;
    }
    var flushableEnd = buffer.length;
    for (var j = 1; j <= buffer.length && j <= maxTagLen; j++) {
      var suffix = buffer.substring(buffer.length - j);
      var holds = false;
      for (var k = 0; k < CLOSE_TAGS.length; k++) {
        if (CLOSE_TAGS[k].indexOf(suffix) === 0) {
          holds = true;
          break;
        }
      }
      if (holds) {
        flushableEnd = buffer.length - j;
        break;
      }
    }
    return flushableEnd;
  }

  // Removes complete console segments, reporting each detail. An opening
  // marker without its close remains in the buffer and is processed as
  // normal text below; split segments are emitted, not retracted.
  function stripCompleteConsoleSegments(buffer, onDetail) {
    var di = buffer.indexOf(CONSOLE_OPEN);
    while (di !== -1) {
      var dci = buffer.indexOf(CONSOLE_CLOSE, di);
      if (dci === -1) break;
      var detail = buffer.substring(di + CONSOLE_OPEN.length, dci);
      if (typeof onDetail === 'function') {
        try {
          onDetail(detail);
        } catch (e) {}
      }
      buffer = buffer.substring(0, di) + buffer.substring(dci + CONSOLE_CLOSE.length);
      di = buffer.indexOf(CONSOLE_OPEN);
    }
    return buffer;
  }

  // Whole-text visible/thinking projection for history. No console stripping.
  function decodeComplete(text) {
    var thinkingParts = [];
    var visibleParts = [];
    var buffer = String(text || '');
    var state = 'visible';
    while (buffer.length > 0) {
      if (state === 'visible') {
        var idx = buffer.indexOf(OPEN_TAG);
        if (idx !== -1) {
          visibleParts.push(buffer.substring(0, idx));
          buffer = buffer.substring(idx + OPEN_TAG.length);
          state = 'thinking';
        } else {
          visibleParts.push(buffer);
          buffer = '';
        }
      } else {
        var close = findEarliestClose(buffer);
        if (close !== null) {
          thinkingParts.push(buffer.substring(0, close.index));
          buffer = buffer.substring(close.index + close.length);
          state = 'visible';
        } else {
          thinkingParts.push(buffer);
          buffer = '';
        }
      }
    }
    return { visible: visibleParts.join(''), thinking: thinkingParts.join('') };
  }

  function createStreamState() {
    return { buffer: '', state: 'visible' };
  }

  function noop() {}

  // Incremental push in wire order: appends chunk, optionally strips
  // complete console segments, then emits flushable segments via
  // onVisible/onThinking as they are found. Partial tag suffixes remain
  // buffered. Sinks: {onVisible, onThinking, onConsoleDetail,
  // stripConsoleDetail}.
  function pushChunk(streamState, chunk, sinks) {
    sinks = sinks || {};
    var onVisible = typeof sinks.onVisible === 'function' ? sinks.onVisible : noop;
    var onThinking = typeof sinks.onThinking === 'function' ? sinks.onThinking : noop;
    var onDetail = typeof sinks.onConsoleDetail === 'function' ? sinks.onConsoleDetail : noop;
    var strip = !!sinks.stripConsoleDetail;

    streamState.buffer += String(chunk || '');
    if (strip) {
      streamState.buffer = stripCompleteConsoleSegments(streamState.buffer, onDetail);
    }

    var buffer = streamState.buffer;
    var state = streamState.state;

    while (buffer.length > 0) {
      if (state === 'visible') {
        var tagStart = buffer.indexOf(OPEN_TAG);
        if (tagStart !== -1) {
          var visiblePart = buffer.substring(0, tagStart);
          if (visiblePart) onVisible(visiblePart);
          buffer = buffer.substring(tagStart + OPEN_TAG.length);
          state = 'thinking';
          continue;
        } else {
          var flushableEnd = visibleFlushEnd(buffer);
          var visibleTail = buffer.substring(0, flushableEnd);
          if (visibleTail) onVisible(visibleTail);
          buffer = buffer.substring(flushableEnd);
          break;
        }
      } else {
        var found = findEarliestClose(buffer);
        if (found !== null) {
          var thinkingPart = buffer.substring(0, found.index);
          if (thinkingPart) onThinking(thinkingPart);
          buffer = buffer.substring(found.index + found.length);
          state = 'visible';
          continue;
        } else {
          var thinkEnd = thinkingFlushEnd(buffer);
          var thinkingTail = buffer.substring(0, thinkEnd);
          if (thinkingTail) onThinking(thinkingTail);
          buffer = buffer.substring(thinkEnd);
          break;
        }
      }
    }

    streamState.buffer = buffer;
    streamState.state = state;
  }

  // Emits the buffered remainder in the current state without console
  // stripping. Chat calls it at EOF/interrupt; regenerate does not.
  function flushRemainder(streamState, sinks) {
    sinks = sinks || {};
    var onVisible = typeof sinks.onVisible === 'function' ? sinks.onVisible : noop;
    var onThinking = typeof sinks.onThinking === 'function' ? sinks.onThinking : noop;
    var buffer = streamState.buffer || '';
    if (!buffer) return;
    if (streamState.state === 'thinking') {
      onThinking(buffer);
    } else {
      onVisible(buffer);
    }
    streamState.buffer = '';
  }

  return {
    OPEN_TAG: OPEN_TAG,
    CLOSE_TAGS: CLOSE_TAGS.slice(),
    CONSOLE_OPEN: CONSOLE_OPEN,
    CONSOLE_CLOSE: CONSOLE_CLOSE,
    decodeComplete: decodeComplete,
    createStreamState: createStreamState,
    pushChunk: pushChunk,
    flushRemainder: flushRemainder
  };
}));
