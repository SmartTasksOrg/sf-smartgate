# Checks the Ruby client against a running server (SMARTGATE_URL, SMARTGATE_AGENT_TOKEN, SMARTGATE_OPERATOR_TOKEN).
require_relative '../lib/smartgate'

def check(ok, what)
  return if ok

  puts "FAIL #{what}"
  exit 1
end

c = SmartGate::Client.new(ENV.fetch('SMARTGATE_URL'), agent_token: ENV['SMARTGATE_AGENT_TOKEN'], operator_token: ENV['SMARTGATE_OPERATOR_TOKEN'])
id = "ruby-#{Process.clock_gettime(Process::CLOCK_REALTIME, :nanosecond)}"
check(c.evaluate({ 'action_id' => "#{id}-a", 'agent_id' => 'ruby-bot', 'action_type' => 'read' })['decision'] == 'allow', 'low action allowed')
check(c.evaluate({ 'action_id' => "#{id}-b", 'agent_id' => 'ruby-bot', 'action_type' => 'delete', 'reversible' => false })['decision'] == 'block', 'high action blocked')
t = "#{id}-c x:y"
c.evaluate({ 'action_id' => t, 'agent_id' => 'ruby-bot-2', 'action_type' => 'read' })
check(c.report(t, 'start')['started'] == true, 'start')
steps = 0
begin
  100.times do |i|
    c.kill(t, 'interop') if i == 5
    c.checkpoint(t)
    steps += 1
    sleep 0.01
  end
rescue SmartGate::Killed
  nil
end
check(steps == 5, 'kill reached the action')
check(c.kill(t)['first'] == false, 'second kill is idempotent')
puts 'ruby client: interop ok'
