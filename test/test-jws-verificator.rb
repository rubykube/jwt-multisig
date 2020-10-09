# encoding: UTF-8
# frozen_string_literal: true

require_relative "test-helper"

class JWSVerificatorTest < Test::Unit::TestCase
  # rubocop:disable Style/NumericLiterals
  def test_trivial_verification_of_signature
    jws     = %({"protected":"eyJhbGciOiJSUzUxMiJ9","header":{"kid":"okunevabednar.io"},"signature":"Lbu_mFwHTsR41og-_sbLW8HN7FXy6tLuC_4hbBWHrnj5HEh4f5RlhXvnyWdew7rXm8hflFj24ESEekFCXcydNUYAO4sr8blYFqoFJVVYoiQRTWM3zA2FzqutOufDDbqbujBpE0xTRT0UqU72kVqczRbFwIY0j-8Aby5B4w5JrUHo2AyWe10hezah886pzu6BO0pfShQZrXgRyFV4Sg63labEMwCL5nhi-bHjeH4ZrUR50NfEOqSOKglI4XniOkYXCIX7zDg4YZc6XEos3CJbh93-AJ_vMJKlJ-s-zVK5av5onI6YZMbKKlgsYL5CyxiJkJSVw4cly5eshixson1HVw"})
    payload = {
      data: { action: "detonate a bomb" },
      exp:  4577496916,
      jti:  "683c7b99-1042-4e1a-81b7-3bc0284d8ec0",
      iss:  "government" }
    example jws, payload, { verify_iss: true, iss: "government" }, payload.to_json
  end
  # rubocop:enable Style/NumericLiterals

  def test_trivial_verification_of_issuer
    jws     = %({"protected":"eyJhbGciOiJIUzM4NCJ9","header":{"kid":"gerhold.co"},"signature":"JQq8ZrqO3DfOXbsdfhzF7qXwAdXunAdjUX_iJoIHOqFWvB7IfHLHYcIVIBUb-AH8"})
    payload = { data: { x: 1 }, iss: "ryaneffertz" }
    e       = assert_raise { example jws, payload, { verify_iss: true, iss: "schumm" }, payload.to_json }
    assert_kind_of JWT::InvalidIssuerError, e
    assert_match(/\binvalid issuer\b/i, e.message)
  end

  def test_protected_data_is_required
    jws     = %({"header":{"kid":"ebert.biz"},"signature":"3nSc9aeRuDyrq_dYQRQX5tnM1wVw6reoUlmQ4JqWIV3LM7yeIDgcVLRYxyb7UUBM0gNqA4QJj3CpwS6vg-EHYQ"})
    payload = { foo: "bar" }
    e       = assert_raise { example jws, payload, {}, payload.to_json }
    assert_kind_of JWT::DecodeError, e
    assert_match(/key not found: "protected"/i, e.message)
  end

  def test_signature_is_required
    jws     = %({"protected":"eyJhbGciOiJSUzI1NiJ9","header":{"kid":"powlowski.info"}})
    payload = {}
    e       = assert_raise { example jws, payload, {}, payload.to_json }
    assert_kind_of JWT::DecodeError, e
    assert_match(/key not found: "signature"/i, e.message)
  end

  def test_protected_data_is_base64_encoded
    jws     = %({"protected":"qwerty","header":{"kid":"rice.com"},"signature":"yVzIjLYCl5gaLHAhKYQmyEnvlYq8rhohYVcyqI-zvTJ0ccU4MojHw9_5GvAyeECF1_DXDvY7wbiyRu4nCN1rMw"})
    payload = {}
    e       = assert_raise { example jws, payload, {}, payload.to_json }
    assert_kind_of JWT::DecodeError, e
    assert_match(/JSON::ParserError/i, e.message.encode("UTF-8", invalid: :replace, undef: :replace))
  end

  def test_header_is_required
    jws     = %({"protected":"eyJhbGciOiJSUzUxMiJ9","signature":"oRN-lE_OqSRtUeI1ZkyftpV2PmJPArrX68_3Zm6BHTxjKemyLHdR2D3z58Fm8a-9XnbRpqpawKDoHx3AB2EKZayw8WChKTZv0qZeUx0SH2oo27nCC9b--99D3_E7D4eqb6qlmML7gAlJyeFbl3QD8qEuMC-EyjSm-kyXmxZcNW5myHC4XZayE0GBfS1yzKYbpSI16PKZOUHoFHjMAHm79bFg37V6FB4qKszMyjss_pl6dK0VdGSiDpX-LPaTdh67joPQHIcmDprfMF0pn50RNvorS-5qa8Ev79mozcDLMUb4hrLXZ_x8AWen6XHbwo34nSrd_Fn7-GOaDtsGc0XdfQ"})
    payload = {}
    e       = assert_raise { example jws, payload, {}, payload.to_json }
    assert_kind_of JWT::DecodeError, e
    assert_match(/key not found: "header"/i, e.message)
  end

  def test_algorithm_is_required
    jws     = %({"protected":"e30","header":{"kid":"wisoky.co"},"signature":"eygCpYrkji7pmmA5sRUFUnwsW-ciZFHSwGVmCSya8Kk"})
    payload = {}
    e       = assert_raise { example jws, payload, {}, payload.to_json }
    assert_kind_of JWT::DecodeError, e
    assert_match(/key not found: "alg"/i, e.message)
  end

  def test_invalid_signature_is_handled_with_exception
    jws     = %({"protected":"eyJhbGciOiJIUzI1NiJ9","header":{"kid":"wisoky.co"},"signature":"qwerty"})
    payload = {}
    e       = assert_raise { example jws, payload, {}, payload.to_json }
    assert_kind_of JWT::VerificationError, e
  end

private

  def example(jws, payload, options, expected)
    encoded_payload = JWT::Base64.url_encode(JSON.dump(payload))
    # Pass instance of OpenSSL::PKey::PKey.
    returned = JWT::Multisig.verify_jws(JSON.parse(jws), encoded_payload, public_keychain, options)
    assert_equal expected, JSON.dump(returned)

    # Pass key in PEM format.
    returned = JWT::Multisig.verify_jws(JSON.parse(jws), encoded_payload, public_keychain, options)
    assert_equal expected, JSON.dump(returned)
  end
end
