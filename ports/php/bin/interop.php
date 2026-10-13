<?php
// Checks the PHP client against a running server (SMARTGATE_URL, SMARTGATE_AGENT_TOKEN, SMARTGATE_OPERATOR_TOKEN).
declare(strict_types=1);
require __DIR__ . '/../src/SmartGate.php';

use SmartGate\{Client, Killed};

$check = function (bool $ok, string $what) { if (!$ok) { echo "FAIL $what\n"; exit(1); } };
$c = new Client(getenv('SMARTGATE_URL'), getenv('SMARTGATE_AGENT_TOKEN'), getenv('SMARTGATE_OPERATOR_TOKEN'));
$id = 'php-' . hrtime(true);
$check($c->evaluate((object) ['action_id' => "$id-a", 'agent_id' => 'php-bot', 'action_type' => 'read'])->decision === 'allow', 'low action allowed');
$check($c->evaluate((object) ['action_id' => "$id-b", 'agent_id' => 'php-bot', 'action_type' => 'delete', 'reversible' => false])->decision === 'block', 'high action blocked');
$t = "$id-c";
$c->evaluate((object) ['action_id' => $t, 'agent_id' => 'php-bot-2', 'action_type' => 'read']);
$check($c->report($t, 'start')->started === true, 'start');
$steps = 0;
try {
    for ($i = 0; $i < 100; $i++) {
        if ($i === 5) $c->kill($t, 'interop');
        $c->checkpoint($t);
        $steps++;
        usleep(10000);
    }
} catch (Killed) {
}
$check($steps === 5, 'kill reached the action');
$check($c->kill($t)->first === false, 'second kill is idempotent');
echo "php client: interop ok\n";
