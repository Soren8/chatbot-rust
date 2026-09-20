(function (root, factory) {
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = factory();
  } else {
    root.ChatVoiceText = factory();
  }
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  // Voice-text boundary: pure helpers shared by the desktop and native
  // voice paths (sentence splitting/termination, TTS normalization,
  // late-fragment joining, amend-vs-new-turn decision, sentence index
  // lookup). No DOM, no thresholds owned here: the amend window stays
  // a chat-owned literal and is passed explicitly so
  // desktop and native keep one shared policy value.

  // Join a late voice fragment onto the previous user utterance.
  function joinVoiceUtterances(previous, next) {
    var prev = String(previous == null ? '' : previous).trim();
    var added = String(next == null ? '' : next).trim();
    if (!prev) return added;
    if (!added) return prev;
    if (added === prev || prev.endsWith(added)) return prev;
    if (added.startsWith(prev)) return added;
    return prev + ' ' + added;
  }

  // True when a new STT result is a continuation of the in-flight voice turn.
  // amendWindowMs is the caller-owned false end-of-speech / quick add-on
  // window; chat passes its owned literal unchanged for both clients.
  function shouldAmendLastVoiceTurn(turnState, amendWindowMs) {
    turnState = turnState || {};
    if (!turnState.lastUserExists || !(turnState.generating || turnState.ttsActive)) return false;
    var endedAt = Number(turnState.lastSpeechEndedAt) || 0;
    var startedAt = Number(turnState.utteranceStartedAt) || 0;
    if (!endedAt || !startedAt) return false;
    return (startedAt - endedAt) <= amendWindowMs;
  }

  // Index of the sentence containing caret offset, or -1.
  function sentenceIndexAtOffset(sentences, offset) {
    if (!sentences || !sentences.length) return -1;
    var o = Math.max(0, offset);
    for (var i = 0; i < sentences.length; i++) {
      var s = sentences[i];
      // Whitespace before the first sentence → first sentence.
      if (o < s.start) return i;
      // Inside [start, end) or on the final character of the sentence.
      if (o < s.end) return i;
      // Exactly at end boundary: if there is a next sentence, caret sits between them → next.
      if (o === s.end && i + 1 < sentences.length) continue;
      if (o === s.end) return i;
    }
    return sentences.length - 1;
  }

  /**
   * Speakable-complete trailing fragment while generation continues.
   * A colon waits for its continuation, a digit period may extend to a
   * decimal, and all-caps, abbreviation, or honorific periods may merge
   * with what streams next.
   */
  function sentenceEndsWithTerminator(sentenceText) {
    const s = String(sentenceText || '').trim();
    if (!s) return false;
    if (!/(?:\.{1,}|[!?…:]|[\r\n])["'”’)\]]*\s*$/.test(s)) return false;
    if (/:\s*["'”’)\]]*\s*$/.test(s)) return false;
    if (/[0-9]\.\s*["'”’)\]]*\s*$/.test(s)) return false;
    if (/\b[A-Z]{2,4}\.\s*["'”’)\]]*\s*$/.test(s)) return false;
    if (/\b(?:e\.g|i\.e|vs|etc|approx|dept|est|apt)\.\s*["'”’)\]]*\s*$/i.test(s)) return false;
    if (/\b(?:Mr|Mrs|Ms|Dr|Prof|Sr|Jr|Gen|Col|Sgt|Lt|Capt|St)\.\s*["'”’)\]]*\s*$/i.test(s)) return false;
    if (/\betcetera\.\s*["'”’)\]]*\s*$/i.test(s)) return false;
    return true;
  }

  /** True if `ch` is an ASCII digit (0-9). */
  function isAsciiDigit(ch) {
    return ch >= '0' && ch <= '9';
  }

  /**
   * Split plain text into sentences. Single algorithm used for:
   * - hover highlight bounds
   * - click-to-play sentence selection
   * - voice-mode discover
   * Do NOT sanitize before splitting (sanitize changes boundaries / can drop the first sentence).
   *
   * Ellipsis "..." / ".." / "…." is ONE terminator — never three empty "." sentences.
   *
   * Decimal/version dots like "4.6", "3.14", "1.2.3" are NOT sentence terminators
   * (a period between two digits is a number separator, not end-of-sentence).
   *
   * @returns {{start:number, end:number, text:string}[]}
   */
  function splitSentences(text) {
    const out = [];
    if (!text) return out;
    let i = 0;
    const n = text.length;
    while (i < n) {
      // Skip whitespace between sentences (not part of either sentence).
      while (i < n && /\s/.test(text.charAt(i))) i++;
      if (i >= n) break;
      const start = i;
      let end = i;
      while (end < n) {
        const c = text.charAt(end);
        // Paragraph break (\n\n or \r\n\r\n) or newline before list marker / heading
        if (c === '\n' || c === '\r') {
          const rest = text.slice(end);
          const isParagraphBreak = /^\r?\n\s*[\r\n]/.test(rest);
          const isListOrHeadingBreak = /^\r?\n\s*(?:[-*]\s+|\d+\.\s+|#{1,6}\s+)/.test(rest);
          if (isParagraphBreak || isListOrHeadingBreak) {
            break;
          }
        }
        // Colon before newline (e.g. "Here are the steps:\n")
        if (c === ':' && end + 1 < n && /^\s*[\r\n]/.test(text.slice(end + 1))) {
          end++;
          break;
        }
        if (c === '.' || c === '!' || c === '?' || c === '\u2026' /* … */) {
          if (c === '.') {
            // Decimal/version dot: digit on BOTH sides → not a terminator.
            // "4.6", "3.14", "1.2.3" stay inside one sentence so TTS does not pause.
            const prev = end > 0 ? text.charAt(end - 1) : '';
            const next = end + 1 < n ? text.charAt(end + 1) : '';
            if (isAsciiDigit(prev) && isAsciiDigit(next)) {
              end++;
              continue;
            }
            // Letter on BOTH sides: "U.S", "e.g", "a.m", "i.e", "domain.com" → not a terminator.
            if (/[a-zA-Z]/.test(prev) && /[a-zA-Z]/.test(next)) {
              end++;
              continue;
            }
            // Numbered list item marker: "1. ", "2. ", "10. " where the sentence chunk
            // so far is purely digits → not a terminator, attach to the item text.
            if (/^\d+$/.test(text.slice(start, end)) && end + 1 < n && /\s/.test(next)) {
              end++;
              continue;
            }
            // Honorific / Title: "Dr. Smith", "Mr. Jones", "Mrs. White" → not a terminator.
            const wordSoFar = text.slice(start, end);
            if (/\b(?:Mr|Mrs|Ms|Dr|Prof|Sr|Jr|Gen|Col|Sgt|Lt|Capt|St)$/i.test(wordSoFar) && end + 1 < n && /\s/.test(next)) {
              end++;
              continue;
            }
            // Common abbreviation followed by comma or space and lowercase letter/digit:
            // "e.g. apples", "i.e. that", "vs. team", "approx. 50" → not a terminator.
            const restAfter = text.slice(end + 1);
            if (/\b(?:e\.g|i\.e|vs|etc|approx|dept|est|apt)$/i.test(wordSoFar) && (/^,\s*/.test(restAfter) || /^\s+[a-z0-9]/.test(restAfter))) {
              end++;
              continue;
            }
            // Dotted initialism followed by lowercase letter: "in the U.S. economy" → not a terminator.
            if (/\b(?:[A-Za-z]\.){1,}[A-Za-z]$/.test(wordSoFar) && /^\s+[a-z]/.test(restAfter)) {
              end++;
              continue;
            }
            // Consume the whole run: "..." is one terminator, not three sentences.
            while (end < n && text.charAt(end) === '.') end++;
          } else if (c === '\u2026') {
            end++;
          } else {
            // ! or ? — keep "?!?!" as a single trailing burst on this sentence.
            while (end < n && (text.charAt(end) === '!' || text.charAt(end) === '?')) end++;
          }
          // Include trailing closers: ..."  )'
          while (end < n && /["'”’)\]]/.test(text.charAt(end))) end++;
          break;
        }
        end++;
      }
      if (end > start) {
        out.push({ start: start, end: end, text: text.slice(start, end) });
      }
      i = end;
    }
    return out;
  }

  // Strip HTML tags until no more are removed (fixpoint). A single global
  // replace is incomplete (CodeQL js/incomplete-multi-character-sanitization):
  // removing one tag can join the text around it into another tag, and
  // replacements running before/after this step can reveal new tags.
  function stripHtmlTags(s) {
    s = String(s == null ? '' : s);
    var prev;
    do {
      prev = s;
      s = s.replace(/<[^>]+>/g, '');
    } while (s !== prev);
    return s;
  }

  // Sanitize raw markdown text for TTS: strip URLs, citations, code blocks, and formatting
  function sanitizeForTTS(text) {
    // Strip tags before URLs: a URL inside a tag attribute would otherwise
    // consume the tag's closing bracket (https?://[^\s)]+ eats ">"), leaving
    // a "<a href="" fragment the later tag strip can no longer match.
    let cleaned = stripHtmlTags(String(text || '')
      // Strip code fences: ```lang ... ``` or standalone ```
      .replace(/```[\s\S]*?```/g, '')
      .replace(/```[a-zA-Z0-9_-]*/g, ''));
    cleaned = cleaned
      // Strip URLs (must come before citation removal)
      .replace(/https?:\/\/[^\s)]+|www\.[^\s)]+/g, '')
      // Strip markdown citation links: [[1]](url) or [[1]]() -> empty
      .replace(/\[\[(\d+)\]\]\([^)]*\)/g, '')
      // Strip remaining markdown links: [text](url) -> text
      .replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')
      // Strip bold/italic: ***text***, **text**, *text*
      .replace(/\*{1,3}([^*]+)\*{1,3}/g, '$1')
      // Strip underline bold/italic: ___text___, __text__, _text_
      .replace(/_{1,3}([^_]+)_{1,3}/g, '$1')
      // Strip strikethrough: ~~text~~
      .replace(/~~([^~]+)~~/g, '$1')
      // Strip inline code: `text`
      .replace(/`([^`]*)`/g, '$1')
      // Strip heading markers: ### heading
      .replace(/^#{1,6}\s+/gm, '')
      // Strip blockquote markers: > quote
      .replace(/^>\s*/gm, '')
      // Strip horizontal rules: --- or *** or ___
      .replace(/^[-*_]{3,}\s*$/gm, '');

    // Strip again after markdown unwrapping: unwrapping can reveal tags that
    // were not plain "<...>" before, and the loop above runs to a fixpoint.
    cleaned = stripHtmlTags(cleaned);

    cleaned = cleaned
      // Normalize CRLF to LF
      .replace(/\r\n/g, '\n')
      // Collapse horizontal whitespace (preserve newlines for paragraph/list sentence discovery)
      .replace(/[^\S\r\n]+/g, ' ')
      // Collapse 3+ newlines into 2
      .replace(/\n{3,}/g, '\n\n')
      .trim();

    // Expand currency with magnitude: $12.6 billion, $12.6B, $12.6 billion dollars
    cleaned = cleaned.replace(/([\$€£])\s*(\d[\d,]*(?:\.\d+)?)\s*(trillion|billion|million|thousand|bn|b|m|k)\b(?:\s*(dollars?|euros?|pounds?))?/gi, (m, sym, amt, mag) => {
      const magLower = mag.toLowerCase();
      const magWord = (magLower === 'k' || magLower === 'thousand') ? 'thousand'
        : (magLower === 'm' || magLower === 'million') ? 'million'
        : (magLower === 'b' || magLower === 'bn' || magLower === 'billion') ? 'billion'
        : (magLower === 'trillion') ? 'trillion' : mag;
      const curr = sym === '€' ? 'euros' : (sym === '£' ? 'pounds' : 'dollars');
      return `${amt} ${magWord} ${curr}`;
    });

    // Expand cents-only: $0.50, $0.01
    cleaned = cleaned.replace(/([\$€£])\s*0\.(\d{1,2})\b(?:\s*(dollars?|euros?|pounds?))?/gi, (m, sym, centsStr) => {
      let cents = parseInt(centsStr, 10) || 0;
      if (centsStr.length === 1) cents *= 10;
      if (sym === '£') return cents === 1 ? '1 penny' : `${cents} pence`;
      return cents === 1 ? '1 cent' : `${cents} cents`;
    });

    // Expand dollars and cents: $12.50, $1.00
    cleaned = cleaned.replace(/([\$€£])\s*(\d[\d,]*)\.(\d{1,2})\b(?:\s*(dollars?|euros?|pounds?))?/gi, (m, sym, intStr, centsStr) => {
      let cents = parseInt(centsStr, 10) || 0;
      if (centsStr.length === 1) cents *= 10;
      const intVal = parseInt(intStr.replace(/,/g, ''), 10) || 0;
      const unit = sym === '€' ? (intVal === 1 ? 'euro' : 'euros')
        : (sym === '£' ? (intVal === 1 ? 'pound' : 'pounds')
        : (intVal === 1 ? 'dollar' : 'dollars'));
      if (cents === 0) return `${intStr} ${unit}`;
      const centsSpoken = sym === '£' ? (cents === 1 ? '1 penny' : `${cents} pence`)
        : (cents === 1 ? '1 cent' : `${cents} cents`);
      return `${intStr} ${unit} and ${centsSpoken}`;
    });

    // Expand integer currency: $5, $1, $100,000
    cleaned = cleaned.replace(/([\$€£])\s*(\d[\d,]*)\b(?:\s*(dollars?|euros?|pounds?))?/gi, (m, sym, amt) => {
      const val = parseInt(amt.replace(/,/g, ''), 10) || 0;
      const unit = sym === '€' ? (val === 1 ? 'euro' : 'euros')
        : (sym === '£' ? (val === 1 ? 'pound' : 'pounds')
        : (val === 1 ? 'dollar' : 'dollars'));
      return `${amt} ${unit}`;
    });

    // Expand Latin abbreviations
    cleaned = cleaned
      .replace(/\be\.g\.,?\s*/gi, 'for example ')
      .replace(/\bi\.e\.,?\s*/gi, 'that is ')
      .replace(/\betc\.\s*$/gim, 'etcetera.')
      .replace(/\betc\.\b/gi, 'etcetera')
      .replace(/\bvs\.?\b/gi, 'versus');

    // Expand titles / honorifics
    cleaned = cleaned.replace(/\b(Dr|Mr|Mrs|Ms|Prof|Sr|Jr|Gen|Col|Sgt|Lt|Capt)\.\s*/g, (m, t) => {
      const map = { Dr: 'Doctor', Mr: 'Mister', Mrs: 'Missus', Ms: 'Ms', Prof: 'Professor', Sr: 'Senior', Jr: 'Junior', Gen: 'General', Col: 'Colonel', Sgt: 'Sergeant', Lt: 'Lieutenant', Capt: 'Captain' };
      return (map[t] || t) + ' ';
    });

    // Common shortened words
    cleaned = cleaned.replace(/\b(approx|dept|apt|est|govt|corp|inc|ltd|co)\.\s*/gi, (m, w) => {
      const map = { approx: 'approximately', dept: 'department', apt: 'apartment', est: 'established', govt: 'government', corp: 'corporation', inc: 'incorporated', ltd: 'limited', co: 'company' };
      return (map[w.toLowerCase()] || w) + ' ';
    });

    // Time: 10 a.m. / 10 p.m.
    cleaned = cleaned.replace(/\b(\d+)\s*([ap])\.m\.\b/gi, '$1 $2M');

    // Symbols
    cleaned = cleaned
      .replace(/(\d+(?:\.\d+)?)\s*°C\b/g, '$1 degrees Celsius')
      .replace(/(\d+(?:\.\d+)?)\s*°F\b/g, '$1 degrees Fahrenheit')
      .replace(/(\d+(?:\.\d+)?)\s*°\b/g, '$1 degrees')
      .replace(/(\d+(?:\.\d+)?)\s*%/g, '$1 percent')
      .replace(/(\w+)\s*&\s*(\w+)/g, '$1 and $2')
      .replace(/#(\d+)\b/g, 'number $1');

    // Dotted initialisms: U.S., U.S.A., A.I., D.C., Ph.D.
    cleaned = cleaned.replace(/\b([A-Z][a-z]?)\.([A-Z][a-z]?)\.(?:([A-Z][a-z]?)\.)*/g, (m, p1, p2, p3, offset, fullStr) => {
      const letters = m.replace(/[^a-zA-Z]/g, '');
      const rest = fullStr.slice(offset + m.length).replace(/^["')\]}”’\s]+/, '');
      const atEnd = !rest || /^[A-Z]/.test(rest);
      return atEnd ? `${letters}.` : letters;
    });

    // If there are no alphanumeric characters, there is nothing speakable
    if (!/[0-9\p{L}]/u.test(cleaned)) {
      return '';
    }
    return cleaned;
  }

  return {
    joinVoiceUtterances: joinVoiceUtterances,
    shouldAmendLastVoiceTurn: shouldAmendLastVoiceTurn,
    sentenceIndexAtOffset: sentenceIndexAtOffset,
    sentenceEndsWithTerminator: sentenceEndsWithTerminator,
    isAsciiDigit: isAsciiDigit,
    splitSentences: splitSentences,
    sanitizeForTTS: sanitizeForTTS
  };
}));
