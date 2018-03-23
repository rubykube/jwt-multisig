# encoding: UTF-8
# frozen_string_literal: true

require_relative "test-helper"

class JWTGeneratorTest < Test::Unit::TestCase
  # rubocop:disable Style/NumericLiterals
  def test_encoding_with_two_signers
    signers  = %w[okon.info gerhold.co]
    payload  = {
      user: { email: "orlo@reynoldsoconnell.co", role: "admin" },
      iat:  1521823259,
      exp:  4677496916,
      jti:  "22cd9c3a-55a7-4024-acb4-17a3ebeeeaac",
      sub:  "session",
      iss:  "raynor",
      aud:  ["hermistonherman"] }
    expected = %({"payload":"eyJ1c2VyIjp7ImVtYWlsIjoib3Jsb0ByZXlub2xkc29jb25uZWxsLmNvIiwicm9sZSI6ImFkbWluIn0sImlhdCI6MTUyMTgyMzI1OSwiZXhwIjo0Njc3NDk2OTE2LCJqdGkiOiIyMmNkOWMzYS01NWE3LTQwMjQtYWNiNC0xN2EzZWJlZWVhYWMiLCJzdWIiOiJzZXNzaW9uIiwiaXNzIjoicmF5bm9yIiwiYXVkIjpbImhlcm1pc3Rvbmhlcm1hbiJdfQ","signatures":[{"protected":"eyJhbGciOiJSUzI1NiJ9","header":{"kid":"okon.info"},"signature":"nPo7Wn_jEkOVBXaqq90eS0MOD_lIJ_6_TD3zCuPnvp1sTTkN79tREI53-YpplWHXEfplJE59npuVqQN7R8k16u4EMAG9OFfU3TRbQ6dj9_syJ-ACiRYiA8J177RAu7BFK4Y2xZHpkdDhxvFmi8ewR98VHWX0XNrMJMdduWsxS1wmEJKGHGzOIynIbEVfrX0LcI-g35f8XbIpe3c5xaVfbtIuR1asSJJ_bFFYGk1STKIfBrfbLvQkTdWZAgZyT5P5WBemkzV56r_PokEZdi_eaQSJf8wt_G6GFZbmFPiaEwDxN5heiCvLjhwXMbTkl3tRdFOEsxAjy7Sg7lhdqBRE9p0GiuBZGgbCLwtGxYoeL6N2oL3-ZoHmC_BoQDhKv0eR65ItcLAKL3o0aviryA59VvQNVZtk3cbGO0IstQRAUbEtYomLoQO8FdYfhR6QpV1zKCb4z5k0MsqAhlNDCOLzfm_OT_JQj404e3pg72k10BlmcXRJR-koHWx9lm0B04hm"},{"protected":"eyJhbGciOiJIUzM4NCJ9","header":{"kid":"gerhold.co"},"signature":"y8r7BD6ivAZfs8WpQoFh6q15teeiXWsYDQd44I3tmrngZ7ZobOH0WvbEjAncgMcM"}]})
    returned = JWT::Multisig.generate_jwt(payload, private_keychain.slice(*signers), algorithms.slice(*signers))
    assert_equal expected, JSON.dump(returned)
  end
  # rubocop:enable Style/NumericLiterals

  # rubocop:disable Style/NumericLiterals
  def test_encoding_with_four_signers
    signers  = %w[okon.info ebert.biz olsonjacobi.name rice.com]
    payload  = {
      data: { currency: "btc", amount: "1.75", destination: "13bwBSNY9Q2ZDMcdCRM5PdjXpJuLiyLLRj" },
      iat:  1521824704,
      exp:  4577496916,
      jti:  "3fb35606-d61a-42df-8c29-d041350d8c60",
      sub:  "withdraw",
      iss:  "oharaupton",
      aud:  %w[douglas crist] }
    expected = %({"payload":"eyJkYXRhIjp7ImN1cnJlbmN5IjoiYnRjIiwiYW1vdW50IjoiMS43NSIsImRlc3RpbmF0aW9uIjoiMTNid0JTTlk5UTJaRE1jZENSTTVQZGpYcEp1TGl5TExSaiJ9LCJpYXQiOjE1MjE4MjQ3MDQsImV4cCI6NDU3NzQ5NjkxNiwianRpIjoiM2ZiMzU2MDYtZDYxYS00MmRmLThjMjktZDA0MTM1MGQ4YzYwIiwic3ViIjoid2l0aGRyYXciLCJpc3MiOiJvaGFyYXVwdG9uIiwiYXVkIjpbImRvdWdsYXMiLCJjcmlzdCJdfQ","signatures":[{"protected":"eyJhbGciOiJSUzI1NiJ9","header":{"kid":"okon.info"},"signature":"lGqBHSPEDRK_JYhwspujZYE-ri_wS56ukF-GT-GKugr0XMsisuYUDj6NLWMBZcHbvg_TQP2LS5C_X4EJlxrJ-mHStp8KvEQtuON-E06PxrOli2j1LgwUPlwrbV9ujfqdwwRblGnOX3mDtXn0XUeWOaIoMBQV4BvfvF-6EuGFTp9bPRNnxyw135GSKxlT6s2IwxUqcXzweK-pzh-OAi6Tny22SSjtP00DqajkhNoDZ66jQMiH8939E09mZhJwABrWqd-v9Saa31RQZp_TOaLuKcMcIVNVcsqFdJyS3J7nsKvclq102lmyD9dZVwteTNOtmpdytpSNoIXK0piBBK3OZ_uYQKkM7dlw-TzIqedTCkpXpxm_x5Q1-SQOt1LuEU4YXdcLFt-G9JrUag-olciMTylo2EISw0dVnRU9ZusX4VwZEU6Z5O0yNAOy1oJYLn72XQud1woR5BXKe9CUZb6maA7WcS5WOJpw2SmkHXVVoQBj1ZbWa6mHLk-lKO3skvk2"},{"protected":"eyJhbGciOiJIUzUxMiJ9","header":{"kid":"ebert.biz"},"signature":"sIQQyqmxM2D8U7O1g3WG2NfLo10HyqFg_fzXfhzuNATJOAxE4YR-Bz_f3srs-bEAOy_bNpfH-9FIDupYLVXpOw"},{"protected":"eyJhbGciOiJSUzM4NCJ9","header":{"kid":"olsonjacobi.name"},"signature":"ZjwWEWZYiNHGwrmbfR7KSdJI6JuqKJ5YcpsfOxs8RZ3XpG0d-7Uua_nzcnm7_DpbyXZfltmH7901gLy8XTFsnRmAeRdpgPDu7s_zTUAW-I-XIMGsGfz5oS_dzoZVjXzW82LxZAC4cZTAS-32AuNReef-SVYJVplJGsdpd633cyMm2QKxM3aQRiuQ7Ogq0tJROtHyuSF4qnmyW75KBOhAWYChc5WjNxLSpaG3WcDV_--NvyYM1INfTWeIYayTE9Y5AB611dRR9w-Cg2qh8JfhBFkOoOuZBfel5Kl94PNST1tp7oLImuuZlgpEEV0_rXd1BAbz7P-XpJEzMGcDuEFEiA"},{"protected":"eyJhbGciOiJIUzUxMiJ9","header":{"kid":"rice.com"},"signature":"rqE6POMDDY35AfoEqPI0rQhTOrGQKPDj4gT8aXC34n6Aw6tOvwx7ULaEPEfAq5T026F3nhvULBbyYP9X5okL8w"}]})
    returned = JWT::Multisig.generate_jwt(payload, private_keychain.slice(*signers), algorithms.slice(*signers))
    assert_equal expected, JSON.dump(returned)
  end
  # rubocop:enable Style/NumericLiterals

  def test_encoding_with_one_signer
    signers  = %w[rice.com]
    payload  = { bar: "baz" }
    expected = %({"payload":"eyJiYXIiOiJiYXoifQ","signatures":[{"protected":"eyJhbGciOiJIUzUxMiJ9","header":{"kid":"rice.com"},"signature":"CnjElUe4Ng1yKiLmG2d6lDWHw-HQDuH_haHM26izIcQDWKe6waF-4uTfPJrzvdh8Jw7A1MOnzUmKBKErivI9Mw"}]})
    returned = JWT::Multisig.generate_jwt(payload, private_keychain.slice(*signers), algorithms.slice(*signers))
    assert_equal expected, JSON.dump(returned)
  end

  def test_algorithm_is_required
    signers = %w[olsonjacobi.name ebert.biz]
    e = assert_raises JWT::EncodeError do
      JWT::Multisig.generate_jwt({}, private_keychain.slice(*signers), algorithms.slice(signers.sample))
    end
    assert_match(/key not found/i, e.message)
  end
end
