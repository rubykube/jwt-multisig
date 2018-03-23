# encoding: UTF-8
# frozen_string_literal: true

require_relative "lib/jwt-multisig/version"

Gem::Specification.new do |s|
  s.name            = "jwt-multisig"
  s.version         = JWT::Multisig::VERSION
  s.author          = "Rubykube"
  s.email           = ""
  s.summary         = ""
  s.description     = ""
  s.homepage        = "https://github.com/rubykube/jwt-multisig"
  s.license         = "MIT"
  s.files           = `git ls-files -z`.split("\x0")
  s.test_files      = `git ls-files -z -- {test,spec,features}/*`.split("\x0")
  s.require_paths   = ["lib"]

  s.add_dependency             "jwt",     "~> 2.1"
  s.add_development_dependency "bundler", "~> 1.16"
end
