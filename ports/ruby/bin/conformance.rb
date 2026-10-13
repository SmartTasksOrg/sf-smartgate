# ruby bin/conformance.rb [dir]: runs spec/conformance against the Ruby port.
require_relative '../lib/smartgate'

dir = ARGV[0] || File.join(__dir__, '..', '..', '..', 'spec', 'conformance')
load_v = ->(n) { JSON.parse(File.read(File.join(dir, n))) }
pol = ->(p) { p.nil? || p == 'default' ? SmartGate::Policy.default : SmartGate::Policy.parse(p) }
c = lambda do |v|
  SmartGate.canonical(v)
rescue ArgumentError => e
  "ERR #{e.message}"
end
total = 0
fails = []
load_v.('canonical.json')['cases'].each do |cs|
  total += 1
  got = c.(cs['value'])
  fails << "canonical/#{cs['name']}: #{got}" unless got == cs['canonical'] && Digest::SHA256.hexdigest(got) == cs['sha256']
end
%w[scoring.json scoring-custom.json].each do |f|
  doc = load_v.(f)
  p = pol.(doc['policy'])
  doc['cases'].each do |cs|
    total += 1
    got = SmartGate::Engine.new(p).decide(cs['action'])
    fails << "#{f}/#{cs['name']}: #{c.(got)}" unless c.(got) == c.(cs['expect'])
  end
end
load_v.('sequences.json')['cases'].each do |cs|
  total += 1
  s = SmartGate::Session.new(pol.(cs['policy']))
  cs['steps'].each_with_index do |st, i|
    got = s.apply(st)
    next if c.(got) == c.(st['expect'])

    fails << "sequences/#{cs['name']}[#{i}]: #{c.(got)}"
    break
  end
end
audit = load_v.('audit.json')
audit['chains'].each do |cs|
  total += 1
  recs = SmartGate.chain(cs['events'])
  fails << "audit/#{cs['name']}" unless c.(recs.map { |r| r['hash'] }) == c.(cs['hashes']) && SmartGate.verify(recs).nil?
end
audit['tampered'].each do |cs|
  total += 1
  idx = SmartGate.verify(cs['records'])
  fails << "audit/tampered/#{cs['name']}: #{idx.inspect}" unless idx == cs['bad_index']
end
load_v.('policies.json')['cases'].each do |cs|
  total += 1
  ok = begin
    SmartGate::Policy.parse(cs['policy'])
    true
  rescue SmartGate::PolicyError
    false
  end
  fails << "policies/#{cs['name']}: valid=#{ok}" unless ok == cs['valid']
end
fails.each { |f| puts "FAIL #{f}" }
if fails.empty?
  puts "ruby: #{total}/#{total} vectors passed"
else
  puts "ruby: #{fails.size} failure(s) of #{total}"
  exit 1
end
