'use strict';
// Runs spec/conformance against this port. Usage: node test/conformance.js [vector dir]
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { dumps, Engine, Session, chain, verify, validate, PolicyError, DEFAULT_POLICY } = require('../src');

const dir = process.argv[2] || path.join(__dirname, '..', '..', '..', 'spec', 'conformance');
const load = (n) => JSON.parse(fs.readFileSync(path.join(dir, n), 'utf8'));
const pol = (p) => (p === undefined || p === null || p === 'default' ? DEFAULT_POLICY : p);
let total = 0;
const fails = [];

for (const c of load('canonical.json').cases) {
  total++;
  const got = dumps(c.value);
  if (got !== c.canonical) fails.push(`canonical/${c.name}: ${got}`);
  else if (crypto.createHash('sha256').update(got, 'utf8').digest('hex') !== c.sha256) fails.push(`canonical/${c.name}: sha256`);
}
for (const f of ['scoring.json', 'scoring-custom.json']) {
  const doc = load(f);
  for (const c of doc.cases) {
    total++;
    const got = new Engine(pol(doc.policy)).decide(c.action);
    if (dumps(got) !== dumps(c.expect)) fails.push(`${f}/${c.name}: ${dumps(got)}`);
  }
}
for (const c of load('sequences.json').cases) {
  total++;
  const s = new Session(pol(c.policy));
  for (let i = 0; i < c.steps.length; i++) {
    const got = s.apply(c.steps[i]);
    if (dumps(got) !== dumps(c.steps[i].expect)) { fails.push(`sequences/${c.name}[${i}]: ${dumps(got)}`); break; }
  }
}
const audit = load('audit.json');
for (const c of audit.chains) {
  total++;
  const recs = chain(c.events);
  if (dumps(recs.map((r) => r.hash)) !== dumps(c.hashes)) fails.push(`audit/${c.name}: hashes`);
  if (!verify(recs).ok) fails.push(`audit/${c.name}: own chain fails`);
}
for (const c of audit.tampered) {
  total++;
  const r = verify(c.records);
  if (r.ok || r.index !== c.bad_index) fails.push(`audit/tampered/${c.name}: ${JSON.stringify(r)}`);
}
for (const c of load('policies.json').cases) {
  total++;
  let ok = true;
  try { validate(c.policy); } catch (e) { if (!(e instanceof PolicyError)) throw e; ok = false; }
  if (ok !== c.valid) fails.push(`policies/${c.name}: valid=${ok}`);
}
for (const f of fails) console.log('FAIL', f);
console.log(fails.length ? `node: ${fails.length} failure(s) of ${total}` : `node: ${total}/${total} vectors passed`);
process.exit(fails.length ? 1 : 0);
