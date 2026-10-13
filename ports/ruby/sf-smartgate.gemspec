# SmartGate for Ruby. Not published on RubyGems; use it from a clone (ruby -Ilib).
Gem::Specification.new do |s|
  s.name = 'sf-smartgate'
  s.version = '0.1.0'
  s.summary = 'SmartGate for Ruby: decision engine, kill registry, audit chain and a client for the SmartGate server.'
  s.license = 'Apache-2.0'
  s.authors = ['SmartTasks Lab']
  s.homepage = 'https://github.com/SmartTasksOrg/sf-smartgate'
  s.files = Dir['lib/**/*']
  s.required_ruby_version = '>= 3.0'
  s.metadata['allowed_push_host'] = 'https://example.invalid'   # not published: refuse `gem push`
end
