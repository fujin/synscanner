
lib = File.expand_path('../lib/', __FILE__)
$:.unshift lib unless $:.include?(lib)

require 'syn/version'

Gem::Specification.new do |s|
  s.name = "syn"
  s.version = Syn::VERSION
  s.platform = Gem::Platform::RUBY
  s.authors = %w[AJ Christensen]
  s.email = %w[aj@junglist.gen.nz]
  s.summary = "a syn scanner extracted from MSF"
  s.description = "portable syn scanner using pcabrub, packetfu & rex"
  s.files = Dir.glob("{bin,lib}/**/*")
  s.executables = %w[syn]
  s.require_path = "lib"
end
