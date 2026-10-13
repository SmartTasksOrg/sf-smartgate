'use strict';
const crypto = require('crypto');
const { dumps } = require('./canonical');

const GENESIS = '0'.repeat(64);

function recordHash(rec) {
  const body = {};
  for (const k of Object.keys(rec)) if (k !== 'hash') body[k] = rec[k];
  return crypto.createHash('sha256').update(dumps(body), 'utf8').digest('hex');
}

class AuditLog {
  constructor(clock = () => Date.now()) { this.records = []; this.prev = GENESIS; this.clock = clock; }
  append(event, fields = {}, tsMs) {
    const rec = { ...fields, seq: this.records.length, ts_ms: tsMs === undefined ? this.clock() : tsMs, event, prev: this.prev };
    rec.hash = recordHash(rec);
    this.prev = rec.hash;
    this.records.push(rec);
    return rec;
  }
}

function chain(events) {
  let prev = GENESIS;
  return events.map((e, i) => {
    const rec = { ...(e.fields || {}), seq: i, ts_ms: e.ts_ms, event: e.event, prev };
    rec.hash = recordHash(rec);
    prev = rec.hash;
    return rec;
  });
}

function verify(records) {
  let prev = GENESIS;
  for (let i = 0; i < records.length; i++) {
    const r = records[i];
    if (r.seq !== i) return { ok: false, index: i, message: `record ${i}: seq is ${r.seq}` };
    if (r.prev !== prev) return { ok: false, index: i, message: `record ${i}: prev does not match` };
    const h = recordHash(r);
    if (r.hash !== h) return { ok: false, index: i, message: `record ${i}: hash does not match` };
    prev = h;
  }
  return { ok: true, index: null, message: `${records.length} records, chain intact` };
}

module.exports = { AuditLog, GENESIS, chain, verify, recordHash };
