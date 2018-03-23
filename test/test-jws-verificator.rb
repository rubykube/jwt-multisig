# encoding: UTF-8
# frozen_string_literal: true

require_relative "test-helper"

class JWSVerificatorTest < Test::Unit::TestCase
  def test_trivial_verification
    jws     = %({"protected":"eyJhbGciOiJSUzUxMiJ9","header":{"kid":"okunevabednar.io"},"signature":"Lbu_mFwHTsR41og-_sbLW8HN7FXy6tLuC_4hbBWHrnj5HEh4f5RlhXvnyWdew7rXm8hflFj24ESEekFCXcydNUYAO4sr8blYFqoFJVVYoiQRTWM3zA2FzqutOufDDbqbujBpE0xTRT0UqU72kVqczRbFwIY0j-8Aby5B4w5JrUHo2AyWe10hezah886pzu6BO0pfShQZrXgRyFV4Sg63labEMwCL5nhi-bHjeH4ZrUR50NfEOqSOKglI4XniOkYXCIX7zDg4YZc6XEos3CJbh93-AJ_vMJKlJ-s-zVK5av5onI6YZMbKKlgsYL5CyxiJkJSVw4cly5eshixson1HVw"})
    payload = {
      data: { action: "detonate a bomb" },
      exp:  4577496916,
      jti:  "683c7b99-1042-4e1a-81b7-3bc0284d8ec0",
      iss:  "government" }
    example jws, payload, { verify_iss: true, iss: "government" }, payload.to_json
  end

  def test_verification_of
    jws     = %({"protected":"eyJhbGciOiJIUzM4NCJ9","header":{"kid":"gerhold.co"},"signature":"JQq8ZrqO3DfOXbsdfhzF7qXwAdXunAdjUX_iJoIHOqFWvB7IfHLHYcIVIBUb-AH8"})
    payload = { data: { x: 1 }, iss: "ryaneffertz" }
    e       = assert_raise { example jws, payload, { verify_iss: true, iss: "schumm" }, payload.to_json }
    assert_kind_of JWT::InvalidIssuerError, e
    assert_match(/\binvalid issuer\b/i, e.message)
  end

private

  def example(jws, payload, options, expected)
    # Pass instance of OpenSSL::PKey::PKey.
    binding.pry if jws.empty?

    returned = JWT::Multisig.verify_jws(JSON.load(jws), payload, public_keychain, options)
    assert_equal expected, JSON.dump(returned)

    # Pass key in PEM format.
    returned = JWT::Multisig.verify_jws(JSON.load(jws), payload, public_keychain, options)
    assert_equal expected, JSON.dump(returned)
  end
end
