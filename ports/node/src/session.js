'use strict';
const { Engine } = require('./engine');
const { Registry } = require('./registry');

// The deterministic core the sequence vectors run (spec/SEMANTICS.md, "Session").
class Session {
  constructor(policy) { this.engine = new Engine(policy); this.registry = new Registry(); }
  apply(step) {
    const r = this.registry;
    switch (step.op) {
      case 'evaluate': {
        const a = step.action;
        const state = r.register(a.action_id, a.agent_id);
        return this.engine.decide(a, { halted: r.isHalted(a.agent_id), killed: state === 'killed' });
      }
      case 'kill': return r.kill(step.action_id, step.reason || '');
      case 'kill_agent': return r.killAgent(step.agent_id, step.reason || '');
      case 'release_agent': return r.releaseAgent(step.agent_id);
      case 'start': return { action_id: step.action_id, started: r.start(step.action_id) };
      case 'complete': return { action_id: step.action_id, state: r.complete(step.action_id) };
      default: throw new Error('unknown op ' + step.op);
    }
  }
}

module.exports = { Session };
