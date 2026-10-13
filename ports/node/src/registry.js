'use strict';
// Action lifecycle and the kill switch (spec/SEMANTICS.md, "Session"). In-memory, single process.
class Killed extends Error {
  constructor(actionId, reason = '') {
    super(`SmartGate killed action ${actionId}${reason ? ': ' + reason : ''}`);
    this.actionId = actionId;
    this.reason = reason;
  }
}

class Registry {
  constructor() { this.actions = new Map(); this.agents = new Map(); this.byAgent = new Map(); }

  isHalted(agentId) { return !!(this.agents.get(agentId) || {}).halted; }

  _index(agentId, actionId) {
    if (!this.byAgent.has(agentId)) this.byAgent.set(agentId, new Set());
    this.byAgent.get(agentId).add(actionId);
  }

  register(actionId, agentId) {
    const cur = this.actions.get(actionId);
    if (cur && cur.agent_id) return cur.state;
    if (cur) { cur.agent_id = agentId; this._index(agentId, actionId); return cur.state; }
    const state = this.isHalted(agentId) ? 'killed' : 'pending';
    this.actions.set(actionId, { action_id: actionId, agent_id: agentId, state, reason: state === 'killed' ? 'agent_halted' : '' });
    this._index(agentId, actionId);
    return state;
  }

  start(actionId) {
    const cur = this.actions.get(actionId);
    if (!cur || cur.state === 'killed' || cur.state === 'completed') return false;
    cur.state = 'running';
    return true;
  }

  complete(actionId) {
    const cur = this.actions.get(actionId);
    if (!cur) return 'unknown';
    if (cur.state === 'pending' || cur.state === 'running') cur.state = 'completed';
    return cur.state;
  }

  kill(actionId, reason = '') {
    const cur = this.actions.get(actionId);
    if (!cur) {
      this.actions.set(actionId, { action_id: actionId, agent_id: null, state: 'killed', reason });
      return { action_id: actionId, status: 'killed', first: true };
    }
    if (cur.state === 'completed') return { action_id: actionId, status: 'completed', first: false, warning: 'already_completed' };
    if (cur.state === 'killed') return { action_id: actionId, status: 'killed', first: false };
    cur.state = 'killed';
    cur.reason = reason;
    return { action_id: actionId, status: 'killed', first: true };
  }

  killAgent(agentId, reason = '') {
    const first = !this.isHalted(agentId);
    if (first) this.agents.set(agentId, { halted: true, reason });
    const killed = [];
    for (const id of [...(this.byAgent.get(agentId) || [])].sort()) {
      const r = this.kill(id, reason || 'agent_halted');
      if (r.status === 'killed' && r.first) killed.push(id);
    }
    return { agent_id: agentId, status: 'halted', first, killed };
  }

  releaseAgent(agentId) {
    const first = this.isHalted(agentId);
    this.agents.set(agentId, { halted: false });
    return { agent_id: agentId, status: 'released', first };
  }

  status(actionId) { return this.actions.get(actionId) || null; }

  checkpoint(actionId) {
    const cur = this.actions.get(actionId);
    if (cur && cur.state === 'killed') throw new Killed(actionId, cur.reason);
  }
}

module.exports = { Registry, Killed };
