# encoding: UTF-8
# frozen_string_literal: true

require "rake/testtask"

Rake::TestTask.new { |t| t.libs << "test" }

task(:release) { Kernel.system "gem build *.gemspec && gem push *.gem && rm *.gem" }
