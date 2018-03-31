# encoding: UTF-8
# frozen_string_literal: true

require_relative "test-helper"

class JWTVerificatorTest < Test::Unit::TestCase
  def test_trivial_verification
    jwt = %({"payload":"eyJpc3MiOiJmb28iLCJiYXIiOnsiYmF6IjoicXV4In19","signatures":[{"protected":"eyJhbGciOiJIUzUxMiJ9","header":{"kid":"ebert.biz"},"signature":"1koPnSwejNF5aCRsqlySX9Td7_gc-dfUkko5G0Svccw-WkBYrwoJJwRJ2Op_-OxjoqSe3ViBGGCbgVUz0khuJQ"},{"protected":"eyJhbGciOiJIUzI1NiJ9","header":{"kid":"wisoky.co"},"signature":"AqtFKTlaVDqg2dOfLBODMhcBlg1gm9ejn6hYQynTyto"},{"protected":"eyJhbGciOiJSUzM4NCJ9","header":{"kid":"hoegerrenner.info"},"signature":"LR9TpJTLwgducdCkN1KmfwXXxd3pp7Xe5fJXJZZM8FVrFrVOEAGQcPnMPIgfPA1UckIXnzih46j4qPOQdotVHEvYvUuvLLT8QQi8y6-vBMlsP-cQehKGpI1T4N5qPzvJqPmhVzZYedWzlvr-VV9wd0BYeBgr65m9BSpFjLFhWVH4NJZuHFPxeYuDEpYoM-lPHdTzdf1E8xd_xwbpz9WpNh0MQib387-wakGWz-UGt9BmJLU8KV01FTAoR0EO9rQfIm5HQ3wGQ7t8U4N4HsOmsXkWF_fRgxjhMHeChDES2awwB4G4KCNw-6ezSBCD7FZcxzbCL2657OEPHNuHA36M91j54jjm1tweYhYJxuUOk5c8j_wSxtieeaORCxOrPp3mshHS_FE0sI_TNNBsIDI_sQwiS08y3d6tv7H4a_MZj_Pe7JWJ3TXlcsaSHy3xuSLYxCZQeLBwJtyz2ERCZOA9ew0BY34tpRwDKxbgF51X7t7uilYxnBn2rBdQeWQKb9q2"}]})
    example jwt, public_keychain, { iss: "foo" }, %({"payload":{"iss":"foo","bar":{"baz":"qux"}},"verified":["ebert.biz","wisoky.co","hoegerrenner.info"],"unverified":[]})
  end

  # rubocop:disable Style/NumericLiterals
  def test_verification_of_two_from_three_signatures
    signers = %w[ebert.biz okunevabednar.io powlowski.info mcglynn.org]
    jwt     = %({"payload":"eyJwYXNzd29yZCI6InNlY3JldCIsImlhdCI6MTUyMjA3NzIyNH0","signatures":[{"protected":"eyJhbGciOiJIUzUxMiJ9","header":{"kid":"ebert.biz"},"signature":"XrreeK0i4zcaEQ0ntKpZVDRzEZLjZUXnWijC73TPC0-1xLK67qSmNt7oxBhnLV8VZVrqvusI-GAE9cEyTPcO4Q"},{"protected":"eyJhbGciOiJSUzUxMiJ9","header":{"kid":"okunevabednar.io"},"signature":"rP4Yx3LcFA9UBHjZCoPQOqETWTblW6FjA4LYoeLe15GTlNRmQLdQYnpaRIpQQ8NP_8PAx5YzIkZNhLEGv2oly0I4FhNp2OBLKw_Mq-XKpwMDKB22gbvZVM1so0fqsh1Muo7V64vk8UkQTlC6Zz_tOlhuH36rMl1YPmypnC6yhO5ocOKU7S50Fzr-s4MmsH2oGaODqvk7U4pKKNjj7Ru8t-4kpmRmYeMTFuS4X6527EIA0Lvav4rsqO_KXFbw8Qokn8hp15OZMgbwYjX_PAbFzFKuR49eUhUyUYotDGoZgO_EhFvEiaF17PEaG9UTCvOXyeMYUbTfjGrXJmo8OgZlnQ"},{"protected":"eyJhbGciOiJSUzI1NiJ9","header":{"kid":"powlowski.info"},"signature":"KhBCjqlwo12p3D-tUgNiRtHS4h71VaKqw4r9974UPKXG3gFdVbZkS3dfPZSpcVOa8cas_Olpv2681BO142yI2vd-0Cm-5imeavb1HPZL6gfYZj4u4peTdA7MkBeBaIz3v6biLcUu0HQEYjg1kom7jlafT-NDx1_AWRd4onD8B9DaB-A0ZR3Hhx5VZrA8CdHz2BiBfNRKiOB4beIW5DN3RIGvxN7XVwnuWato06yytZuMWidVfAwDoO7Kyu3V3rOLDf-c92lxQyAw9VlIBMuerfdTD-H11sw-dqY6N-dyIfFhg7a97hFCB_as4TrY5Tdn1uHVokfkrgoz73eZDxPjDSVyIiZDzJZuh1PxparJgktfVl0531ihi5ehFTA2Vi26tz2qha1IhgzTzU_Mxoq15UcI8jcmFuJeP3lr8KJY-dP5oEMcSlTV4xsDgyyf5E8JBSgRSC4jy7dxmRc7n4MRYaY6yK1aWS4y1xwBNkFMk6L09QTUHX3r9XE9alo6rgi6bhi5yMSty8k7XEmUqIINWvm_JzGTzkuBpbFtLWzRKjhz_M79lOyn13si6iYXrjbjCs1_DFurtCu_r_k0ry_WsDGyEHazqgdCY6FM6cRQ00i0NtDS_V7s3IaOdLKHmg_f3C8wIOFJMz3qB1nUNPrn4u-UEHDxBrSzSGyT98AkNOs"},{"protected":"eyJhbGciOiJIUzI1NiJ9","header":{"kid":"mcglynn.org"},"signature":"gTMqrByZC7cpLxHob1WYnUAsu3HYTgasHJvdQcVuBag"}]})
    example jwt, public_keychain.slice(*signers.first(2)), { iat_leeway: 3153600000 }, %({"payload":{"password":"secret","iat":1522077224},"verified":["ebert.biz","okunevabednar.io"],"unverified":["powlowski.info","mcglynn.org"]})
  end
  # rubocop:enable Style/NumericLiterals

  def test_verification_of_reserved_fields
    jwt = %({"payload":"eyJ4IjoieSJ9","signatures":[{"protected":"eyJhbGciOiJSUzM4NCJ9","header":{"kid":"olsonjacobi.name"},"signature":"qSYw9q_auEHYUwMvGCPRKdBIkqTzTnqIbZ-v9cq4wCkFGz0kk0J0VC3aA6E9ghT49UY9lh6j0TbvaEjPSaP4EWWjawE5hk31_h2Db5-lmgARtxCuESWkWvwaroPidtsNST3yHRS6_YFZ-QBXEgkOnMRDDBnd5cXJeaAahIVXS1mUVtTGttWpg6s577Cnmw2zo7vTAbq9Yg7-Y1s2wRzCF8oablahDXjyrc5aRfzml33Qjvafo_o6BlUJ_D_rI5lmR0Y0E_i7H6wLXtT_jp7E0ORs3dp40SSzkNIcnbPpXx0Zp8y32Dw7_mxYrclKeaPEmQ_DpuhYMGrp9iNF15JjKA"}]})
    e   = assert_raise do
      example jwt, public_keychain, { verify_jti: true }, %({"payload":{"x":"y"},"verified":["olsonjacobi.name"],"unverified":[]})
    end
    assert_kind_of JWT::DecodeError, e
    assert_match(/missing jti/i, e.message)
  end

  def test_verification_with_empty_keychain
    jwt = %({"payload":"eyJ4eHgiOiJ6enoifQ","signatures":[{"protected":"eyJhbGciOiJSUzM4NCJ9","header":{"kid":"hoegerrenner.info"},"signature":"TE-XldA2YE3sERvW-ue7GU2lY32ZlV1NxymkEdtoTTsqFgliU8ggqbevLD0USpC-xQgdGJjOE2x2qm0wE4jxGRlJo70eHCqVz8I4s5b-h5OwbG2chRm7kZ0xiYnlV-Q_99tiT101EXOTys_QSEG2TnNhHwGXPPpinzcc_0ND8ATt9Gu5zmOq4sQdYyLY9ELOW6o8nHumPw4DTv2VBN5TAHEGASfstjN2MgME4-f3NYy82iBB75gCkHq1DnLWWfLLBpHdJR9f0L9rgILw0l6QUjf5OHhp_LjoK_qH2IVnjBCGQBkH12TEINZO2ZJygnWrqIx3bAgwzjcqKm9rgVRNG7IQ4G2luPp_usT2X0qsa-kWQm2id3FavaaWe5wkeL154V0e0hE7CVXH33GQ7af7EaDw4Lxqs3C0_10xOVoOeOxjYB9upDfr5Pmilu3NRiWYErRAfBfZ624KDpjtwcwjK2QcUh1jUceGuItQiMveIRxCflifbHGk4-rx8AYup4nw"},{"protected":"eyJhbGciOiJSUzI1NiJ9","header":{"kid":"powlowski.info"},"signature":"AX4UR4Hul7TxsTusfW4afQbV_fz-gbcaYgmXMqA_pUOPWZZcFKaZhfHRuII66DYXR_zrkrjtILxNWf5AbFsJZeMY3pWFurV0eqz5HVLTSZVYFxpCCkwL8E_lSk9tEkXh-YVMgeLgrDky3CtONtdl4qHj0YPN9Q7teFspx-v_mWwoIxuCS9o87uTJzmYHjPN2tF26ngNsNTl_y18R_CkP5XN1E9rZPccbyEuecbKJBCMIKwGCyfwBFvYVxu2rizNA6FBdchtFfRKq_jfVUbWDQpFQgR9GqmelZk1lm63KfnOAHG-49XzIQbFA7BF4IxVqVlp9uZG-cJlrnlllvhjknAyCdKjI-XIVDyubWNrpZG8HpxLweydzb0Ba9G97cvMBGEadMhjCxu54-lOyHoDqFstqOPZL8MlczxWFtcz1tM2EwBv0HZ6Tq7lCKQ0a5BeAyNWrJnoHIAlMxhaYw_Hs-C9hLjj37t5Zv5YrIwBC9gWHvTfpr1ifTL3ETKl6e5LG2Oq0--TflZNAnIYdIRV1OlAly7qhyqupEcjkqoizWDr90OX4lFzQssWY1WLq1fWwI1o0acPSvnRObhUjpfja4ZE92S98kW5BpHIN6qmtCezfLGIWfkhqLqSMfIrrP784kRauKNLxE9l3I6SAmYADCEzVe7nHSLVdwSx4KWCvh5g"}]})
    example jwt, {}, {}, %({"payload":{"xxx":"zzz"},"verified":[],"unverified":["hoegerrenner.info","powlowski.info"]})
  end

  def test_both_symbols_and_strings_are_supported
    jwt      = %({"payload":"eyJpc3MiOiJmb28iLCJiYXIiOnsiYmF6IjoicXV4In19","signatures":[{"protected":"eyJhbGciOiJIUzUxMiJ9","header":{"kid":"ebert.biz"},"signature":"1koPnSwejNF5aCRsqlySX9Td7_gc-dfUkko5G0Svccw-WkBYrwoJJwRJ2Op_-OxjoqSe3ViBGGCbgVUz0khuJQ"},{"protected":"eyJhbGciOiJIUzI1NiJ9","header":{"kid":"wisoky.co"},"signature":"AqtFKTlaVDqg2dOfLBODMhcBlg1gm9ejn6hYQynTyto"},{"protected":"eyJhbGciOiJSUzM4NCJ9","header":{"kid":"hoegerrenner.info"},"signature":"LR9TpJTLwgducdCkN1KmfwXXxd3pp7Xe5fJXJZZM8FVrFrVOEAGQcPnMPIgfPA1UckIXnzih46j4qPOQdotVHEvYvUuvLLT8QQi8y6-vBMlsP-cQehKGpI1T4N5qPzvJqPmhVzZYedWzlvr-VV9wd0BYeBgr65m9BSpFjLFhWVH4NJZuHFPxeYuDEpYoM-lPHdTzdf1E8xd_xwbpz9WpNh0MQib387-wakGWz-UGt9BmJLU8KV01FTAoR0EO9rQfIm5HQ3wGQ7t8U4N4HsOmsXkWF_fRgxjhMHeChDES2awwB4G4KCNw-6ezSBCD7FZcxzbCL2657OEPHNuHA36M91j54jjm1tweYhYJxuUOk5c8j_wSxtieeaORCxOrPp3mshHS_FE0sI_TNNBsIDI_sQwiS08y3d6tv7H4a_MZj_Pe7JWJ3TXlcsaSHy3xuSLYxCZQeLBwJtyz2ERCZOA9ew0BY34tpRwDKxbgF51X7t7uilYxnBn2rBdQeWQKb9q2"}]})
    keychain = {
      "hoegerrenner.info": public_keychain["hoegerrenner.info"],
      "wisoky.co": public_keychain["wisoky.co"],
      "ebert.biz" => public_keychain["ebert.biz"] }
    example jwt, keychain, { iss: "foo" }, %({"payload":{"iss":"foo","bar":{"baz":"qux"}},"verified":["ebert.biz","wisoky.co","hoegerrenner.info"],"unverified":[]})
  end

private

  def example(jwt, keychain, options, expected)
    returned = JWT::Multisig.verify_jwt(JSON.parse(jwt), keychain, options)
    assert_equal expected, JSON.dump(returned)
  end
end
