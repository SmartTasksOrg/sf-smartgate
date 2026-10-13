'use strict';
// Canonical JSON (spec/SEMANTICS.md): sorted ASCII keys, no whitespace, minimal escapes, integers only.
const SHORT = { '"': '\\"', '\\': '\\\\', '\b': '\\b', '\f': '\\f', '\n': '\\n', '\r': '\\r', '\t': '\\t' };

function str(s) {
  let out = '"';
  for (const ch of s) {
    if (SHORT[ch] !== undefined) out += SHORT[ch];
    else if (ch.codePointAt(0) < 0x20) out += '\\u' + ch.codePointAt(0).toString(16).padStart(4, '0');
    else out += ch;
  }
  return out + '"';
}

function dumps(v) {
  if (v === null || v === undefined) return 'null';
  if (v === true) return 'true';
  if (v === false) return 'false';
  if (typeof v === 'number') {
    if (!Number.isInteger(v)) throw new TypeError('canonical JSON allows integers only');
    return String(v);
  }
  if (typeof v === 'string') return str(v);
  if (Array.isArray(v)) return '[' + v.map(dumps).join(',') + ']';
  if (typeof v === 'object') {
    const keys = Object.keys(v).filter((k) => v[k] !== undefined);
    for (const k of keys) if (!/^[\x00-\x7f]*$/.test(k)) throw new TypeError('keys must be ASCII');
    keys.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    return '{' + keys.map((k) => str(k) + ':' + dumps(v[k])).join(',') + '}';
  }
  throw new TypeError('cannot encode ' + typeof v);
}

module.exports = { dumps };
