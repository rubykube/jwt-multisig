# encoding: UTF-8
# frozen_string_literal: true

require_relative "lib/jwt-multisig/version"

Gem::Specification.new do |s|
  s.name            = "jwt-multisig"
  s.version         = JWT::Multisig::VERSION
  s.author          = "RubyKube"
  s.email           = "support@rubykube.io"
  s.summary         = "The tool for working with multi-signature JWT."
  s.description     = "The tool for working with JWT signed by multiple " \
                      "verificators as per RFC 7515. Based on the RubyGem «jwt» under the hood."
  s.homepage        = "https://github.com/rubykube/jwt-multisig"
  s.license         = "MIT"
  s.files           = `git ls-files -z`.split("\x0")
  s.test_files      = `git ls-files -z -- {test,spec,features}/*`.split("\x0")
  s.require_paths   = ["lib"]

  s.add_dependency             "jwt",           "~> 2.2"
  s.add_dependency             "activesupport", ">= 4.0"
  s.add_development_dependency "bundler",       "~> 1.17"
end
