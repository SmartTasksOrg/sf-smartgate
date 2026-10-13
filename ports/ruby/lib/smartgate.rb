# frozen_string_literal: true

# SmartGate for Ruby: policy, decision engine, kill registry, session, audit chain (spec/SEMANTICS.md)
# and a client for the SmartGate server. Standard library only.
require 'json'
require 'digest'
require 'net/http'
require 'uri'
require 'monitor'

module SmartGate
  FRICTIONS = %w[allow prompt block].freeze
  GENESIS = '0' * 64

  class PolicyError < StandardError; end
  class ActionError < StandardError; end

  class Killed < StandardError
    attr_reader :action_id, :reason

    def initialize(action_id, reason = '')
      @action_id = action_id
      @reason = reason
      super("SmartGate killed action #{action_id}: #{reason}")
    end
  end

  SHORT = { '"' => '\\"', '\\' => '\\\\', "\b" => '\\b', "\f" => '\\f', "\n" => '\\n', "\r" => '\\r', "\t" => '\\t' }.freeze

  def self.canon_str(s)
    out = +'"'
    s.each_char do |ch|
      out << if SHORT.key?(ch) then SHORT[ch]
             elsif ch.ord < 0x20 then format('\\u%04x', ch.ord)
             else ch
             end
    end
    out << '"'
  end

  # Canonical JSON: sorted ASCII keys, minimal escapes, integers only.
  def self.canonical(v)
    case v
    when nil then 'null'
    when true then 'true'
    when false then 'false'
    when Integer then v.to_s
    when Float then raise ArgumentError, 'canonical JSON allows integers only'
    when String then canon_str(v)
    when Array then "[#{v.map { |x| canonical(x) }.join(',')}]"
    when Hash
      v.each_key { |k| raise ArgumentError, 'keys must be ASCII' unless k.to_s.ascii_only? }
      "{#{v.keys.map(&:to_s).sort.map { |k| "#{canon_str(k)}:#{canonical(v.key?(k) ? v[k] : v[k.to_sym])}" }.join(',')}}"
    else raise ArgumentError, "cannot encode #{v.class}"
    end
  end

  def self.int_in(v, what, lo, hi)
    raise PolicyError, "#{what} must be an integer" unless v.is_a?(Integer)
    raise PolicyError, "#{what} must be between #{lo} and #{hi}" if v < lo || v > hi

    v
  end

  def self.friction(v, what)
    raise PolicyError, "#{what} must be one of allow, prompt, block" unless FRICTIONS.include?(v)

    v
  end

  def self.stronger(a, b)
    FRICTIONS.index(a) >= FRICTIONS.index(b) ? a : b
  end

  BIG = 2**62

  class Policy
    attr_reader :bands, :floors, :default_floor, :irreversible_bonus, :levels, :cascade, :low_confidence, :approval_timeout_ms, :fallback

    def self.default
      parse(JSON.parse(File.read(File.join(__dir__, 'smartgate', 'policy.default.json'))))
    end

    # Validate and read a parsed policy (spec/conformance/policies.json).
    def self.parse(doc)
      new(doc)
    end

    def initialize(doc)
      raise PolicyError, 'policy must be a JSON object' unless doc.is_a?(Hash)
      raise PolicyError, 'schema must be "smartgate.policy/v1"' unless doc['schema'] == 'smartgate.policy/v1'

      bands = doc['cost_bands']
      raise PolicyError, 'cost_bands must be a non-empty list' unless bands.is_a?(Array) && !bands.empty?

      @bands = []
      last = nil
      bands.each_with_index do |b, i|
        raise PolicyError, "cost_bands[#{i}] must be an object" unless b.is_a?(Hash)

        sc = SmartGate.int_in(b['score'], "cost_bands[#{i}].score", 0, 10)
        m = b['max_usd']
        if m.nil?
          raise PolicyError, 'only the last band may have max_usd null' unless i == bands.size - 1
        else
          raise PolicyError, "cost_bands[#{i}].max_usd must be a number" unless m.is_a?(Numeric)
          raise PolicyError, 'cost_bands max_usd must increase' if last && m <= last

          last = m
        end
        @bands << [m, sc]
      end
      raise PolicyError, 'the last band must have max_usd null' unless @bands.last[0].nil?

      @floors = {}
      if doc.key?('action_floors')
        raise PolicyError, 'action_floors must be an object' unless doc['action_floors'].is_a?(Hash)

        doc['action_floors'].each { |k, v| @floors[k] = SmartGate.int_in(v, "action_floors.#{k}", 0, 10) }
      end
      @default_floor = doc.key?('default_floor') ? SmartGate.int_in(doc['default_floor'], 'default_floor', 0, 10) : 0
      @irreversible_bonus = doc.key?('irreversible_bonus') ? SmartGate.int_in(doc['irreversible_bonus'], 'irreversible_bonus', 0, 10) : 0
      levels = doc['levels']
      raise PolicyError, 'levels must be a non-empty list' unless levels.is_a?(Array) && !levels.empty?

      @levels = []
      prev = -1
      names = {}
      levels.each_with_index do |l, i|
        name = l.is_a?(Hash) ? l['name'] : nil
        raise PolicyError, "levels[#{i}] needs a name" unless name.is_a?(String) && !name.empty?
        raise PolicyError, "level name #{name} repeated" if names[name]

        names[name] = true
        ms = SmartGate.int_in(l['max_score'], "levels[#{i}].max_score", 0, 10)
        raise PolicyError, 'levels max_score must increase' if ms <= prev

        prev = ms
        @levels << [name, ms, SmartGate.friction(l['friction'], "levels[#{i}].friction")]
      end
      raise PolicyError, 'the last level must have max_score 10' unless prev == 10

      @cascade = nil
      unless doc['cascade'].nil?
        c = doc['cascade']
        raise PolicyError, 'cascade must be an object or null' unless c.is_a?(Hash)

        @cascade = [SmartGate.int_in(c['window_ms'], 'cascade.window_ms', 1, BIG), SmartGate.int_in(c['max_actions'], 'cascade.max_actions', 1, BIG),
                    SmartGate.int_in(c['max_cumulative_risk'], 'cascade.max_cumulative_risk', 0, BIG), SmartGate.friction(c['escalate_to'], 'cascade.escalate_to')]
      end
      @low_confidence = nil
      unless doc['low_confidence'].nil?
        c = doc['low_confidence']
        raise PolicyError, 'low_confidence must be an object or null' unless c.is_a?(Hash)

        @low_confidence = [SmartGate.int_in(c['below_permille'], 'low_confidence.below_permille', 0, 1000), SmartGate.friction(c['escalate_to'], 'low_confidence.escalate_to')]
      end
      @approval_timeout_ms = 300_000
      if doc.key?('approval')
        a = doc['approval']
        raise PolicyError, 'approval must be an object' unless a.is_a?(Hash)

        @approval_timeout_ms = SmartGate.int_in(a['timeout_ms'], 'approval.timeout_ms', 1, BIG) if a.key?('timeout_ms')
        raise PolicyError, 'approval.on_timeout must be reject or approve' if a.key?('on_timeout') && !%w[reject approve].include?(a['on_timeout'])
      end
      @fallback = 'allow'
      return unless doc.key?('fallback')
      raise PolicyError, 'fallback must be allow, block or block_high' unless %w[allow block block_high].include?(doc['fallback'])

      @fallback = doc['fallback']
    end
  end

  def self.check_action(a)
    raise ActionError, 'action must be an object' unless a.is_a?(Hash)

    %w[action_id agent_id action_type].each do |k|
      raise ActionError, "action.#{k} must be a non-empty string" unless a[k].is_a?(String) && !a[k].empty?
    end
    cost = a.fetch('cost_usd', 0)
    raise ActionError, 'action.cost_usd must be a number >= 0' unless cost.is_a?(Numeric) && cost >= 0
    raise ActionError, 'action.reversible must be true or false' unless [true, false].include?(a.fetch('reversible', true))

    c = a['confidence_permille']
    raise ActionError, 'action.confidence_permille must be an integer 0-1000' unless c.nil? || (c.is_a?(Integer) && c.between?(0, 1000))

    ts = a.fetch('ts_ms', 0)
    raise ActionError, 'action.ts_ms must be an integer >= 0' unless ts.is_a?(Integer) && ts >= 0
    raise ActionError, 'action.target must be a string' unless a['target'].nil? || a['target'].is_a?(String)

    a
  end

  def self.score(p, a)
    cost = a.fetch('cost_usd', 0)
    s = p.bands.last[1]
    p.bands.each do |m, sc|
      if m.nil? || cost <= m
        s = sc
        break
      end
    end
    s = [s, p.floors.fetch(a['action_type'], p.default_floor)].max
    s += p.irreversible_bonus if a.fetch('reversible', true) == false
    s.clamp(0, 10)
  end

  def self.level_of(p, s)
    p.levels.find { |l| s <= l[1] } || p.levels.last
  end

  class Engine
    attr_reader :policy

    def initialize(policy = nil)
      @policy = policy || Policy.default
      @hist = {}
      @mutex = Mutex.new
    end

    def decide(action, halted: false, killed: false)
      a = SmartGate.check_action(action)
      p = @policy
      s = SmartGate.score(p, a)
      name, _, fr = SmartGate.level_of(p, s)
      reasons = ["GATE-LEVEL-#{name.upcase}"]
      reasons << 'GATE-UNLISTED-TYPE' unless p.floors.key?(a['action_type'])
      cascade = false
      if p.cascade
        w, max, risk, esc = p.cascade
        ts = a.fetch('ts_ms', 0)
        @mutex.synchronize do
          h = (@hist[a['agent_id']] || []).select { |e| e[0] >= ts - w }
          h << [ts, s]
          @hist[a['agent_id']] = h
          cascade = h.size > max && h.sum { |e| e[1] } > risk
        end
        if cascade
          fr = SmartGate.stronger(fr, esc)
          reasons << 'GATE-CASCADE'
        end
      end
      conf = a['confidence_permille']
      if p.low_confidence && !conf.nil? && conf < p.low_confidence[0]
        fr = SmartGate.stronger(fr, p.low_confidence[1])
        reasons << 'GATE-LOW-CONFIDENCE'
      end
      if halted
        fr = 'block'
        reasons << 'GATE-AGENT-HALTED'
      end
      if killed
        fr = 'block'
        reasons << 'GATE-KILLED'
      end
      { 'action_id' => a['action_id'], 'agent_id' => a['agent_id'], 'decision' => fr, 'score' => s, 'level' => name,
        'reasons' => reasons, 'cascade' => cascade }
    end
  end

  class Registry
    def initialize
      @actions = {} # id => [agent|nil, state, reason]
      @halted = {}
      @by_agent = Hash.new { |h, k| h[k] = {} }
      @mutex = Monitor.new
    end

    def halted?(agent) = @mutex.synchronize { @halted.fetch(agent, false) }

    def register(id, agent)
      @mutex.synchronize do
        if (cur = @actions[id])
          if cur[0].nil?
            cur[0] = agent
            @by_agent[agent][id] = true
          end
          return cur[1]
        end
        h = halted?(agent)
        @actions[id] = [agent, h ? 'killed' : 'pending', h ? 'agent_halted' : '']
        @by_agent[agent][id] = true
        @actions[id][1]
      end
    end

    def start(id)
      @mutex.synchronize do
        cur = @actions[id]
        return false if cur.nil? || %w[killed completed].include?(cur[1])

        cur[1] = 'running'
        true
      end
    end

    def complete(id)
      @mutex.synchronize do
        cur = @actions[id]
        return 'unknown' if cur.nil?

        cur[1] = 'completed' if %w[pending running].include?(cur[1])
        cur[1]
      end
    end

    def kill(id, reason = '')
      @mutex.synchronize do
        cur = @actions[id]
        if cur.nil?
          @actions[id] = [nil, 'killed', reason]
          return { 'action_id' => id, 'status' => 'killed', 'first' => true }
        end
        return { 'action_id' => id, 'status' => 'completed', 'first' => false, 'warning' => 'already_completed' } if cur[1] == 'completed'
        return { 'action_id' => id, 'status' => 'killed', 'first' => false } if cur[1] == 'killed'

        cur[1] = 'killed'
        cur[2] = reason
        { 'action_id' => id, 'status' => 'killed', 'first' => true }
      end
    end

    def kill_agent(agent, reason = '')
      @mutex.synchronize do
        first = !halted?(agent)
        @halted[agent] = true
        killed = @by_agent[agent].keys.sort.select do |id|
          r = kill(id, reason.empty? ? 'agent_halted' : reason)
          r['status'] == 'killed' && r['first']
        end
        { 'agent_id' => agent, 'status' => 'halted', 'first' => first, 'killed' => killed }
      end
    end

    def release_agent(agent)
      @mutex.synchronize do
        first = halted?(agent)
        @halted[agent] = false
        { 'agent_id' => agent, 'status' => 'released', 'first' => first }
      end
    end

    def checkpoint(id)
      cur = @mutex.synchronize { @actions[id] }
      raise Killed.new(id, cur[2]) if cur && cur[1] == 'killed'
    end
  end

  # The deterministic core the sequence vectors run.
  class Session
    attr_reader :engine, :registry

    def initialize(policy)
      @engine = Engine.new(policy)
      @registry = Registry.new
    end

    def apply(step)
      r = @registry
      id = step['action_id']
      reason = step['reason'] || ''
      case step['op']
      when 'evaluate'
        a = step['action']
        st = r.register(a['action_id'], a['agent_id'])
        @engine.decide(a, halted: r.halted?(a['agent_id']), killed: st == 'killed')
      when 'kill' then r.kill(id, reason)
      when 'kill_agent' then r.kill_agent(step['agent_id'], reason)
      when 'release_agent' then r.release_agent(step['agent_id'])
      when 'start' then { 'action_id' => id, 'started' => r.start(id) }
      when 'complete' then { 'action_id' => id, 'state' => r.complete(id) }
      else raise ArgumentError, "unknown op #{step['op']}"
      end
    end
  end

  # Percent-encode one path segment (a space becomes %20, not +).
  def self.seg(id)
    URI.encode_www_form_component(id).gsub('+', '%20')
  end

  def self.record_hash(rec)
    Digest::SHA256.hexdigest(canonical(rec.reject { |k, _| k == 'hash' }))
  end

  def self.chain(events)
    prev = GENESIS
    events.each_with_index.map do |e, i|
      rec = (e['fields'] || {}).merge('seq' => i, 'ts_ms' => e['ts_ms'], 'event' => e['event'], 'prev' => prev)
      rec['hash'] = record_hash(rec)
      prev = rec['hash']
      rec
    end
  end

  # Index of the first bad record, or nil.
  def self.verify(records)
    prev = GENESIS
    records.each_with_index do |r, i|
      return i unless r['seq'] == i && r['prev'] == prev

      h = begin
        record_hash(r)
      rescue ArgumentError
        return i
      end
      return i unless r['hash'] == h

      prev = h
    end
    nil
  end

  class ServerError < StandardError
    attr_reader :status

    def initialize(status, body)
      @status = status
      super("SmartGate server answered #{status}: #{body}")
    end
  end

  # Client for the SmartGate server (Net::HTTP). Fallback when the connection fails: allow (the council's
  # default), block, block_high. When the request may have reached the server but no answer came (read
  # timeout, reset), evaluate answers block (GATE-NO-ANSWER). A checkpoint always asks the server, so an
  # action admitted on the fallback still learns of a kill once the server is back.
  class Client
    attr_accessor :fallback, :policy

    def initialize(url, agent_token: nil, operator_token: nil, timeout: 2)
      @uri = URI(url.sub(%r{/+\z}, ''))
      @agent_token = agent_token
      @operator_token = operator_token
      @timeout = timeout
      @policy = Policy.default
      @fallback = @policy.fallback
    end

    def call(method, path, body, token)
      req = (method == 'GET' ? Net::HTTP::Get : Net::HTTP::Post).new(path)
      req['Content-Type'] = 'application/json'
      req['Authorization'] = "Bearer #{token}" if token && !token.empty?
      req.body = JSON.generate(body) unless body.nil?
      res = Net::HTTP.start(@uri.host, @uri.port, use_ssl: @uri.scheme == 'https', open_timeout: @timeout, read_timeout: @timeout) { |h| h.request(req) }
      raise ServerError.new(res.code.to_i, res.body) if res.code.to_i >= 300

      res.body.to_s.empty? ? {} : JSON.parse(res.body)
    end

    def evaluate(action)
      call('POST', '/smartgate/evaluate', action, @agent_token)
    rescue Net::ReadTimeout, Errno::ECONNRESET, EOFError => e
      a = SmartGate.check_action(action)
      warn "SmartGate did not answer (#{e.message}); blocking #{a['action_id']}"
      { 'action_id' => a['action_id'], 'agent_id' => a['agent_id'], 'decision' => 'block', 'reasons' => ['GATE-NO-ANSWER'], 'cascade' => false }
    rescue SystemCallError, Net::OpenTimeout, SocketError, IOError => e
      a = SmartGate.check_action(action)
      s = SmartGate.score(@policy, a)
      name, _, fr = SmartGate.level_of(@policy, s)
      d = @fallback == 'block' || (@fallback == 'block_high' && fr == 'block') ? 'block' : 'allow'
      warn "SmartGate unreachable (#{e.message}); fallback #{@fallback} -> #{d}"
      { 'action_id' => a['action_id'], 'agent_id' => a['agent_id'], 'decision' => d, 'score' => s, 'level' => name,
        'reasons' => ["GATE-FALLBACK-#{@fallback.upcase.tr('_', '-')}"], 'cascade' => false, 'fallback' => true }
    end

    def status(id) = call('GET', "/smartgate/actions/#{SmartGate.seg(id)}", nil, @agent_token)
    def report(id, what) = call('POST', "/smartgate/actions/#{SmartGate.seg(id)}/#{what}", {}, @agent_token)

    # Raises Killed once the action has been killed; a network error is ignored (fallback rule).
    def checkpoint(id)
      st = begin
        status(id)
      rescue ServerError => e
        raise unless e.status == 404

        return nil # unknown to the server (admitted on the fallback)
      rescue SystemCallError, Net::OpenTimeout, Net::ReadTimeout, SocketError, IOError
        return nil # cannot ask: keep going
      end
      raise Killed.new(id, st['reason'].to_s) if st['state'] == 'killed'
    end

    def kill(action_id, reason = '') = call('POST', '/smartgate/kill', { 'action_id' => action_id, 'reason' => reason }, @operator_token)
    def kill_agent(agent_id, reason = '') = call('POST', '/smartgate/kill', { 'agent_id' => agent_id, 'reason' => reason }, @operator_token)
  end
end
