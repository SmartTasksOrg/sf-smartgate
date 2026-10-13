<?php
// SmartGate for PHP: policy, decision engine, kill registry, session, audit chain (spec/SEMANTICS.md)
// and a client for the SmartGate server. JSON objects are decoded as arrays; use SmartGate\decode().
declare(strict_types=1);

namespace SmartGate;

const FRICTIONS = ['allow', 'prompt', 'block'];

final class PolicyError extends \RuntimeException {}
final class ActionError extends \RuntimeException {}
final class Killed extends \RuntimeException {
    public function __construct(public readonly string $actionId, public readonly string $reason = '') {
        parent::__construct("SmartGate killed action $actionId: $reason");
    }
}

/** Decode JSON keeping objects distinct from lists: objects become \stdClass. */
function decode(string $json): mixed {
    return json_decode($json, false, 512, JSON_THROW_ON_ERROR | JSON_BIGINT_AS_STRING);
}

function canon_str(string $s): string {
    $out = '"';
    foreach (mb_str_split($s, 1, 'UTF-8') as $ch) {
        $o = mb_ord($ch, 'UTF-8');
        $out .= match ($ch) {
            '"' => '\\"', '\\' => '\\\\', "\x08" => '\\b', "\f" => '\\f', "\n" => '\\n', "\r" => '\\r', "\t" => '\\t',
            default => $o < 0x20 ? sprintf('\\u%04x', $o) : $ch,
        };
    }
    return $out . '"';
}

/** Canonical JSON of a decoded value (stdClass objects, lists, scalars). Floats are an error. */
function canonical(mixed $v): string {
    if ($v === null) return 'null';
    if ($v === true) return 'true';
    if ($v === false) return 'false';
    if (is_int($v)) return (string) $v;
    if (is_float($v)) throw new \InvalidArgumentException('canonical JSON allows integers only');
    if (is_string($v)) return canon_str($v);
    if (is_array($v) && array_is_list($v)) return '[' . implode(',', array_map(__NAMESPACE__ . '\canonical', $v)) . ']';
    $a = (array) $v;
    $keys = array_map('strval', array_keys($a));
    foreach ($keys as $k) if (preg_match('/[^\x00-\x7f]/', $k)) throw new \InvalidArgumentException('keys must be ASCII');
    sort($keys, SORT_STRING);
    $parts = [];
    foreach ($keys as $k) $parts[] = canon_str($k) . ':' . canonical($a[$k]);
    return '{' . implode(',', $parts) . '}';
}

function has(object $o, string $k): bool { return property_exists($o, $k); }

function int_in(mixed $v, string $what, int $lo, int $hi): int {
    if (!is_int($v)) throw new PolicyError("$what must be an integer");
    if ($v < $lo || $v > $hi) throw new PolicyError("$what must be between $lo and $hi");
    return $v;
}

function friction(mixed $v, string $what): string {
    if (!is_string($v) || !in_array($v, FRICTIONS, true)) throw new PolicyError("$what must be one of allow, prompt, block");
    return $v;
}

function stronger(string $a, string $b): string {
    return array_search($a, FRICTIONS, true) >= array_search($b, FRICTIONS, true) ? $a : $b;
}

final class Policy {
    public array $bands = [];        // [max|null, score]
    public array $floors = [];
    public int $defaultFloor = 0;
    public int $irreversibleBonus = 0;
    public array $levels = [];       // [name, max, friction]
    public ?array $cascade = null;   // [window, max_actions, max_risk, escalate]
    public ?array $lowConfidence = null;
    public int $approvalTimeoutMs = 300000;
    public string $fallback = 'allow';

    public static function default(): Policy {
        return self::parse(decode(file_get_contents(__DIR__ . '/policy.default.json')));
    }

    /** Validate and read a decoded policy (spec/conformance/policies.json). */
    public static function parse(mixed $doc): Policy {
        if (!($doc instanceof \stdClass)) throw new PolicyError('policy must be a JSON object');
        if (($doc->schema ?? null) !== 'smartgate.policy/v1') throw new PolicyError('schema must be "smartgate.policy/v1"');
        $p = new Policy();
        $bands = $doc->cost_bands ?? null;
        if (!is_array($bands) || !$bands) throw new PolicyError('cost_bands must be a non-empty list');
        $last = null;
        foreach ($bands as $i => $b) {
            if (!($b instanceof \stdClass)) throw new PolicyError("cost_bands[$i] must be an object");
            $s = int_in($b->score ?? null, "cost_bands[$i].score", 0, 10);
            $m = $b->max_usd ?? null;
            if ($m === null) {
                if ($i !== count($bands) - 1) throw new PolicyError('only the last band may have max_usd null');
            } else {
                if (!is_int($m) && !is_float($m)) throw new PolicyError("cost_bands[$i].max_usd must be a number");
                if ($last !== null && $m <= $last) throw new PolicyError('cost_bands max_usd must increase');
                $last = $m;
            }
            $p->bands[] = [$m, $s];
        }
        if (end($p->bands)[0] !== null) throw new PolicyError('the last band must have max_usd null');
        if (has($doc, 'action_floors')) {
            if (!($doc->action_floors instanceof \stdClass)) throw new PolicyError('action_floors must be an object');
            foreach ((array) $doc->action_floors as $k => $v) $p->floors[(string) $k] = int_in($v, "action_floors.$k", 0, 10);
        }
        if (has($doc, 'default_floor')) $p->defaultFloor = int_in($doc->default_floor, 'default_floor', 0, 10);
        if (has($doc, 'irreversible_bonus')) $p->irreversibleBonus = int_in($doc->irreversible_bonus, 'irreversible_bonus', 0, 10);
        $levels = $doc->levels ?? null;
        if (!is_array($levels) || !$levels) throw new PolicyError('levels must be a non-empty list');
        $prev = -1;
        $names = [];
        foreach ($levels as $i => $l) {
            $name = ($l instanceof \stdClass) ? ($l->name ?? null) : null;
            if (!is_string($name) || $name === '') throw new PolicyError("levels[$i] needs a name");
            if (isset($names[$name])) throw new PolicyError("level name $name repeated");
            $names[$name] = true;
            $ms = int_in($l->max_score ?? null, "levels[$i].max_score", 0, 10);
            if ($ms <= $prev) throw new PolicyError('levels max_score must increase');
            $prev = $ms;
            $p->levels[] = [$name, $ms, friction($l->friction ?? null, "levels[$i].friction")];
        }
        if ($prev !== 10) throw new PolicyError('the last level must have max_score 10');
        if (($doc->cascade ?? null) !== null) {
            $c = $doc->cascade;
            if (!($c instanceof \stdClass)) throw new PolicyError('cascade must be an object or null');
            $p->cascade = [int_in($c->window_ms ?? null, 'cascade.window_ms', 1, PHP_INT_MAX), int_in($c->max_actions ?? null, 'cascade.max_actions', 1, PHP_INT_MAX),
                int_in($c->max_cumulative_risk ?? null, 'cascade.max_cumulative_risk', 0, PHP_INT_MAX), friction($c->escalate_to ?? null, 'cascade.escalate_to')];
        }
        if (($doc->low_confidence ?? null) !== null) {
            $c = $doc->low_confidence;
            if (!($c instanceof \stdClass)) throw new PolicyError('low_confidence must be an object or null');
            $p->lowConfidence = [int_in($c->below_permille ?? null, 'low_confidence.below_permille', 0, 1000), friction($c->escalate_to ?? null, 'low_confidence.escalate_to')];
        }
        if (has($doc, 'approval')) {
            $a = $doc->approval;
            if (!($a instanceof \stdClass)) throw new PolicyError('approval must be an object');
            if (has($a, 'timeout_ms')) $p->approvalTimeoutMs = int_in($a->timeout_ms, 'approval.timeout_ms', 1, PHP_INT_MAX);
            if (has($a, 'on_timeout') && !in_array($a->on_timeout, ['reject', 'approve'], true)) throw new PolicyError('approval.on_timeout must be reject or approve');
        }
        if (has($doc, 'fallback')) {
            if (!in_array($doc->fallback, ['allow', 'block', 'block_high'], true)) throw new PolicyError('fallback must be allow, block or block_high');
            $p->fallback = $doc->fallback;
        }
        return $p;
    }
}

/** Check an action (stdClass) and return it as a normalised array. */
function check_action(mixed $a): array {
    if (!($a instanceof \stdClass)) throw new ActionError('action must be an object');
    $out = [];
    foreach (['action_id', 'agent_id', 'action_type'] as $k) {
        $v = $a->$k ?? null;
        if (!is_string($v) || $v === '') throw new ActionError("action.$k must be a non-empty string");
        $out[$k] = $v;
    }
    $cost = has($a, 'cost_usd') ? $a->cost_usd : 0;
    if ((!is_int($cost) && !is_float($cost)) || $cost < 0) throw new ActionError('action.cost_usd must be a number >= 0');
    $out['cost_usd'] = $cost;
    $rev = has($a, 'reversible') ? $a->reversible : true;
    if (!is_bool($rev)) throw new ActionError('action.reversible must be true or false');
    $out['reversible'] = $rev;
    $c = $a->confidence_permille ?? null;
    if ($c !== null && (!is_int($c) || $c < 0 || $c > 1000)) throw new ActionError('action.confidence_permille must be an integer 0-1000');
    $out['confidence_permille'] = $c;
    $ts = has($a, 'ts_ms') ? $a->ts_ms : 0;
    if (!is_int($ts) || $ts < 0) throw new ActionError('action.ts_ms must be an integer >= 0');
    $out['ts_ms'] = $ts;
    $t = $a->target ?? null;
    if ($t !== null && !is_string($t)) throw new ActionError('action.target must be a string');
    return $out;
}

function score(Policy $p, array $a): int {
    $s = end($p->bands)[1];
    foreach ($p->bands as [$m, $sc]) {
        if ($m === null || $a['cost_usd'] <= $m) { $s = $sc; break; }
    }
    $s = max($s, $p->floors[$a['action_type']] ?? $p->defaultFloor);
    if ($a['reversible'] === false) $s += $p->irreversibleBonus;
    return max(0, min(10, $s));
}

function level_of(Policy $p, int $s): array {
    foreach ($p->levels as $l) if ($s <= $l[1]) return $l;
    return end($p->levels);
}

final class Engine {
    private array $hist = [];
    public function __construct(public Policy $policy) {}

    public function decide(array $a, bool $halted = false, bool $killed = false): \stdClass {
        $p = $this->policy;
        $s = score($p, $a);
        [$name, , $fr] = level_of($p, $s);
        $reasons = ['GATE-LEVEL-' . strtoupper($name)];
        if (!array_key_exists($a['action_type'], $p->floors)) $reasons[] = 'GATE-UNLISTED-TYPE';
        $cascade = false;
        if ($p->cascade !== null) {
            [$w, $max, $risk, $esc] = $p->cascade;
            $h = array_values(array_filter($this->hist[$a['agent_id']] ?? [], fn ($e) => $e[0] >= $a['ts_ms'] - $w));
            $h[] = [$a['ts_ms'], $s];
            $this->hist[$a['agent_id']] = $h;
            $cascade = count($h) > $max && array_sum(array_column($h, 1)) > $risk;
            if ($cascade) { $fr = stronger($fr, $esc); $reasons[] = 'GATE-CASCADE'; }
        }
        if ($p->lowConfidence !== null && $a['confidence_permille'] !== null && $a['confidence_permille'] < $p->lowConfidence[0]) {
            $fr = stronger($fr, $p->lowConfidence[1]);
            $reasons[] = 'GATE-LOW-CONFIDENCE';
        }
        if ($halted) { $fr = 'block'; $reasons[] = 'GATE-AGENT-HALTED'; }
        if ($killed) { $fr = 'block'; $reasons[] = 'GATE-KILLED'; }
        return (object) ['action_id' => $a['action_id'], 'agent_id' => $a['agent_id'], 'decision' => $fr, 'score' => $s,
            'level' => $name, 'reasons' => $reasons, 'cascade' => $cascade];
    }
}

final class Registry {
    private array $actions = [];   // id => [agent|null, state, reason]
    private array $halted = [];
    private array $byAgent = [];

    public function isHalted(string $agent): bool { return $this->halted[$agent] ?? false; }

    public function register(string $id, string $agent): string {
        if (isset($this->actions[$id])) {
            if ($this->actions[$id][0] === null) { $this->actions[$id][0] = $agent; $this->byAgent[$agent][$id] = true; }
            return $this->actions[$id][1];
        }
        $h = $this->isHalted($agent);
        $this->actions[$id] = [$agent, $h ? 'killed' : 'pending', $h ? 'agent_halted' : ''];
        $this->byAgent[$agent][$id] = true;
        return $this->actions[$id][1];
    }

    public function start(string $id): bool {
        $c = $this->actions[$id] ?? null;
        if ($c === null || $c[1] === 'killed' || $c[1] === 'completed') return false;
        $this->actions[$id][1] = 'running';
        return true;
    }

    public function complete(string $id): string {
        if (!isset($this->actions[$id])) return 'unknown';
        if (in_array($this->actions[$id][1], ['pending', 'running'], true)) $this->actions[$id][1] = 'completed';
        return $this->actions[$id][1];
    }

    public function kill(string $id, string $reason = ''): \stdClass {
        $c = $this->actions[$id] ?? null;
        if ($c === null) {
            $this->actions[$id] = [null, 'killed', $reason];
            return (object) ['action_id' => $id, 'status' => 'killed', 'first' => true];
        }
        if ($c[1] === 'completed') return (object) ['action_id' => $id, 'status' => 'completed', 'first' => false, 'warning' => 'already_completed'];
        if ($c[1] === 'killed') return (object) ['action_id' => $id, 'status' => 'killed', 'first' => false];
        $this->actions[$id][1] = 'killed';
        $this->actions[$id][2] = $reason;
        return (object) ['action_id' => $id, 'status' => 'killed', 'first' => true];
    }

    public function killAgent(string $agent, string $reason = ''): \stdClass {
        $first = !$this->isHalted($agent);
        $this->halted[$agent] = true;
        $ids = array_map('strval', array_keys($this->byAgent[$agent] ?? []));
        sort($ids, SORT_STRING);
        $killed = [];
        foreach ($ids as $id) {
            $r = $this->kill($id, $reason === '' ? 'agent_halted' : $reason);
            if ($r->status === 'killed' && $r->first) $killed[] = $id;
        }
        return (object) ['agent_id' => $agent, 'status' => 'halted', 'first' => $first, 'killed' => $killed];
    }

    public function releaseAgent(string $agent): \stdClass {
        $first = $this->isHalted($agent);
        $this->halted[$agent] = false;
        return (object) ['agent_id' => $agent, 'status' => 'released', 'first' => $first];
    }

    public function checkpoint(string $id): void {
        $c = $this->actions[$id] ?? null;
        if ($c !== null && $c[1] === 'killed') throw new Killed($id, $c[2]);
    }
}

/** The deterministic core the sequence vectors run. */
final class Session {
    public Engine $engine;
    public Registry $registry;
    public function __construct(Policy $p) { $this->engine = new Engine($p); $this->registry = new Registry(); }

    public function apply(\stdClass $step): \stdClass {
        $id = $step->action_id ?? '';
        $reason = $step->reason ?? '';
        switch ($step->op) {
            case 'evaluate':
                $a = check_action($step->action);
                $st = $this->registry->register($a['action_id'], $a['agent_id']);
                return $this->engine->decide($a, $this->registry->isHalted($a['agent_id']), $st === 'killed');
            case 'kill': return $this->registry->kill($id, $reason);
            case 'kill_agent': return $this->registry->killAgent($step->agent_id, $reason);
            case 'release_agent': return $this->registry->releaseAgent($step->agent_id);
            case 'start': return (object) ['action_id' => $id, 'started' => $this->registry->start($id)];
            case 'complete': return (object) ['action_id' => $id, 'state' => $this->registry->complete($id)];
        }
        throw new \InvalidArgumentException('unknown op');
    }
}

const GENESIS = '0000000000000000000000000000000000000000000000000000000000000000';

function record_hash(\stdClass $rec): string {
    $body = clone $rec;
    unset($body->hash);
    return hash('sha256', canonical($body));
}

/** Build audit records from [{event, ts_ms, fields}]. */
function chain(array $events): array {
    $prev = GENESIS;
    $out = [];
    foreach ($events as $i => $e) {
        $rec = isset($e->fields) ? clone $e->fields : new \stdClass();
        $rec->seq = $i; $rec->ts_ms = $e->ts_ms; $rec->event = $e->event; $rec->prev = $prev;
        $rec->hash = record_hash($rec);
        $prev = $rec->hash;
        $out[] = $rec;
    }
    return $out;
}

/** Index of the first bad record, or -1. */
function verify(array $records): int {
    $prev = GENESIS;
    foreach ($records as $i => $r) {
        if (($r->seq ?? null) !== $i) return $i;
        if (($r->prev ?? null) !== $prev) return $i;
        try { $h = record_hash($r); } catch (\InvalidArgumentException) { return $i; }
        if (($r->hash ?? null) !== $h) return $i;
        $prev = $h;
    }
    return -1;
}

/** Client for the SmartGate server (PHP streams). Fallback when the connection fails: allow (the council's
 *  default), block, block_high. When the request may have reached the server but no answer came (timeout),
 *  evaluate answers block (GATE-NO-ANSWER). A checkpoint always asks the server, so an action admitted on the
 *  fallback still learns of a kill once the server is back. */
final class Client {
    public string $fallback;
    public Policy $policy;
    public function __construct(public string $url, public string $agentToken = '', public string $operatorToken = '', public float $timeout = 2.0) {
        $this->url = rtrim($url, '/');
        $this->policy = Policy::default();
        $this->fallback = $this->policy->fallback;
    }

    public string $lastError = '';

    /** @return array{0:int,1:mixed} status and decoded body; status 0 = network error ($lastError says which) */
    public function call(string $method, string $path, mixed $body, string $token): array {
        $hdr = "Content-Type: application/json\r\n" . ($token !== '' ? "Authorization: Bearer $token\r\n" : '');
        $ctx = stream_context_create(['http' => ['method' => $method, 'header' => $hdr, 'content' => $body === null ? '' : json_encode($body),
            'timeout' => $this->timeout, 'ignore_errors' => true]]);
        $text = @file_get_contents($this->url . $path, false, $ctx);
        if ($text === false) { $this->lastError = (string) (error_get_last()['message'] ?? ''); return [0, null]; }
        $status = 0;
        foreach ($http_response_header ?? [] as $h) if (preg_match('#^HTTP/\S+ (\d+)#', $h, $m)) $status = (int) $m[1];
        return [$status, $text === '' ? new \stdClass() : decode($text)];
    }

    private function ok(array $r): \stdClass {
        if ($r[0] === 0) throw new \RuntimeException('SmartGate server unreachable');
        if ($r[0] >= 300) throw new \RuntimeException("SmartGate server answered {$r[0]}");
        return $r[1];
    }

    public function evaluate(\stdClass $action): \stdClass {
        $r = $this->call('POST', '/smartgate/evaluate', $action, $this->agentToken);
        if ($r[0] !== 0) return $this->ok($r);
        $a = check_action($action);
        if (!preg_match('/refused|getaddrinfo|resolve|unreachable|No route/i', $this->lastError)) {
            error_log("SmartGate did not answer ({$this->lastError}); blocking {$a['action_id']}");
            return (object) ['action_id' => $a['action_id'], 'agent_id' => $a['agent_id'], 'decision' => 'block',
                'reasons' => ['GATE-NO-ANSWER'], 'cascade' => false];
        }
        $s = score($this->policy, $a);
        [$name, , $fr] = level_of($this->policy, $s);
        $d = $this->fallback === 'block' || ($this->fallback === 'block_high' && $fr === 'block') ? 'block' : 'allow';
        error_log("SmartGate unreachable; fallback {$this->fallback} -> $d for {$a['action_id']}");
        return (object) ['action_id' => $a['action_id'], 'agent_id' => $a['agent_id'], 'decision' => $d, 'score' => $s, 'level' => $name,
            'reasons' => ['GATE-FALLBACK-' . strtoupper(str_replace('_', '-', $this->fallback))], 'cascade' => false, 'fallback' => true];
    }

    public function status(string $id): \stdClass { return $this->ok($this->call('GET', '/smartgate/actions/' . rawurlencode($id), null, $this->agentToken)); }
    public function report(string $id, string $what): \stdClass { return $this->ok($this->call('POST', '/smartgate/actions/' . rawurlencode($id) . "/$what", new \stdClass(), $this->agentToken)); }

    /** Throws Killed once the action has been killed; a network error is ignored (fallback rule). */
    public function checkpoint(string $id): void {
        $r = $this->call('GET', '/smartgate/actions/' . rawurlencode($id), null, $this->agentToken);
        if ($r[0] === 0 || $r[0] === 404) return;     // unreachable, or unknown to the server (admitted on the fallback)
        $st = $this->ok($r);
        if (($st->state ?? '') === 'killed') throw new Killed($id, (string) ($st->reason ?? ''));
    }

    public function kill(string $actionId, string $reason = ''): \stdClass {
        return $this->ok($this->call('POST', '/smartgate/kill', (object) ['action_id' => $actionId, 'reason' => $reason], $this->operatorToken));
    }

    public function killAgent(string $agentId, string $reason = ''): \stdClass {
        return $this->ok($this->call('POST', '/smartgate/kill', (object) ['agent_id' => $agentId, 'reason' => $reason], $this->operatorToken));
    }
}
