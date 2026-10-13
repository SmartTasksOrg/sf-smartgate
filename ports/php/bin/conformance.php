<?php
// php bin/conformance.php [dir]: runs spec/conformance against the PHP port.
declare(strict_types=1);
require __DIR__ . '/../src/SmartGate.php';

use function SmartGate\{canonical, chain, verify, check_action, decode};
use SmartGate\{Engine, Policy, PolicyError, Session};

$dir = $argv[1] ?? __DIR__ . '/../../../spec/conformance';
$load = fn (string $n) => decode(file_get_contents("$dir/$n"));
$pol = fn ($p) => ($p === null || $p === 'default') ? Policy::default() : Policy::parse($p);
$c = function ($v): string { try { return canonical($v); } catch (\InvalidArgumentException $e) { return 'ERR ' . $e->getMessage(); } };
$total = 0;
$fails = [];
foreach ($load('canonical.json')->cases as $cs) {
    $total++;
    $got = $c($cs->value);
    if ($got !== $cs->canonical || hash('sha256', $got) !== $cs->sha256) $fails[] = "canonical/{$cs->name}: $got";
}
foreach (['scoring.json', 'scoring-custom.json'] as $f) {
    $doc = $load($f);
    $p = $pol($doc->policy ?? null);
    foreach ($doc->cases as $cs) {
        $total++;
        $got = (new Engine($p))->decide(check_action($cs->action));
        if ($c($got) !== $c($cs->expect)) $fails[] = "$f/{$cs->name}: " . $c($got);
    }
}
foreach ($load('sequences.json')->cases as $cs) {
    $total++;
    $s = new Session($pol($cs->policy ?? null));
    foreach ($cs->steps as $i => $st) {
        $got = $s->apply($st);
        if ($c($got) !== $c($st->expect)) { $fails[] = "sequences/{$cs->name}[$i]: " . $c($got); break; }
    }
}
$audit = $load('audit.json');
foreach ($audit->chains as $cs) {
    $total++;
    $recs = chain($cs->events);
    if ($c(array_map(fn ($r) => $r->hash, $recs)) !== $c($cs->hashes) || verify($recs) !== -1) $fails[] = "audit/{$cs->name}";
}
foreach ($audit->tampered as $cs) {
    $total++;
    $idx = verify($cs->records);
    if ($idx !== $cs->bad_index) $fails[] = "audit/tampered/{$cs->name}: $idx";
}
foreach ($load('policies.json')->cases as $cs) {
    $total++;
    $ok = true;
    try { Policy::parse($cs->policy); } catch (PolicyError) { $ok = false; }
    if ($ok !== $cs->valid) $fails[] = "policies/{$cs->name}: valid=" . var_export($ok, true);
}
foreach ($fails as $f) echo "FAIL $f\n";
if ($fails) { echo 'php: ' . count($fails) . " failure(s) of $total\n"; exit(1); }
echo "php: $total/$total vectors passed\n";
