# encoding: UTF-8
# frozen_string_literal: true

require_relative "test-helper"

class JWSGeneratorTest < Test::Unit::TestCase
  def test_trivial_generation
    [
      ["wisoky.co", { data: [{ x: 1 }, { y: 2 }, { z: 3 }] }, %({"protected":"eyJhbGciOiJIUzI1NiJ9","header":{"kid":"wisoky.co"},"signature":"83XVcMqm7pMa0tvgCHWsjyPCOdGfWnc0-czu96n_Efw"})],
      ["powlowski.info", { data: [{ x: 1 }, { y: 2 }, { z: 3 }] }, %({"protected":"eyJhbGciOiJSUzI1NiJ9","header":{"kid":"powlowski.info"},"signature":"lXJ9N_c87BxxjhB162zTNuGhoBxjBdot6E8UEhDczmWhctQTZgzTTPrMa3X9fVLVkc57tucQh13eVU6p3gAppqy6Y2B5933BiCeQdHHao5sEOcXwbIvFMi-IOcloFXHhEw8IzIa6ZlugmWII_eHZGHF3czLqkww9pjUBPYI7Z5EinG4Co7rySIM8D2XzQZ7Q-c_05StpjYIeGszY8ihJkKm0aDLnVMIoQo_22vwl1rXHUd8XBUg020Oqwxk1iI49YkzxdDdOJO5M2RqYCHn5hi8QpVAU0zzag8gHjfB12A5c-rAVl3Pj_EBjNN3FEo9Xb1L860uAKHAO8XUjNFujGJdQ_ANUkT0CbGq4wB0JXY4ml8nN_ROOTjHpDalbHXojv80OW0GFSWRCKLNQ24OiFsesTBOHBnszYtHaTep37GdL4GZogUNyHzX7jggq904WTfwVkVUJtzkCUE-9D1jdwv8mpTRdYDO4sX2AlbhSOEW8AIjCmTr__ai4mAUK0JLJ3_dvFQHG7cXahPyh3MPsR4Rk1tl2VJ1o4Ont_SxfAM3l8ssgpaaFUSkYxhCIo7rT2VThSOI9FVbf7eakIZG0n3jv562jABh5nsmX9k9gBxkMMKLw4tw0URjtpERLj9x0K3EP-NpJT0-GD3nHU3lSxgZFSXbCNJa38Z1GeJBcPtE"})],
      ["mcglynn.org", { data: [{ x: 1 }, { y: 2 }, { z: 3 }] }, %({"protected":"eyJhbGciOiJIUzI1NiJ9","header":{"kid":"mcglynn.org"},"signature":"MAttuD_FCMFOTAcGlJJinPRoe3NHqWp5-ImFvVevv30"})],
      ["ebert.biz", { data: [{ x: 1 }, { y: 2 }, { z: 3 }] }, %({"protected":"eyJhbGciOiJIUzUxMiJ9","header":{"kid":"ebert.biz"},"signature":"g5sDKJSix8I8RbLd4l3exK6TH0TCJNbd9xV5MMt0xL16PGPX9pLC8ukvkjrncdGQEHTmEpbTp-AROigRdBS8yg"})],
      ["olsonjacobi.name", { data: [{ x: 1 }, { y: 2 }, { z: 3 }] }, %({"protected":"eyJhbGciOiJSUzM4NCJ9","header":{"kid":"olsonjacobi.name"},"signature":"P4uy4N7L_Fox0KuRQtV8TT3xeX8-EV6ZU8a-csDqC0IpCFBfgmCZr2yg3TdCogAS-R3ZKbfiooL8GyqkmSZt_A-HXd0O4NY4MokHmn2AQun7pWzytKu8zYa1spZVncKmvaGeS8NEpzc7nA7cYbpF7oYsMN0_oWwkUkJHAacDVIy7hbUHNYQbR0Tx9eJwLWrLEeU6Mk9fNKjT5MvpKzi5gHlUNtXEniEP3Y9hkU206_9w52yIKbiefZC5xB108JCrRM-yIePMRW3IUwAk8CP_bGEJQ4cuwl-6r1P_Wpdip7xrARFSLmn4FhdR-XKVA41bCBDt3bVuRFtMcUhuGOk44A"})],
      ["okunevabednar.io", { data: [{ x: 1 }, { y: 2 }, { z: 3 }] }, %({"protected":"eyJhbGciOiJSUzUxMiJ9","header":{"kid":"okunevabednar.io"},"signature":"LesBgs8x3DNynPhoqSTiVoIRd9gl-Y8yntMvVe8-7Xe9KAlxExNCUaCJgsfIidCMD69O_D7wIsSlxIqFRj8K8bCpn7LGQm5pxOJlHy_UPvOVczuiTp50nynxcXimAfBoLHPA8d8EcVDo9CgjJszehOggIQJxMusiAcTCVgWMf__TziMa-IIB1MMMGsmnoZCmMdF_eQpthYIjOVIz6wXzNS7RhcYPD48lVO0Q56sGK1hS1ejM1l6qKeUQQp3PbN9G24OAvIlhVMlrOLDPCS3dwKQZjgtaNcNyNVeoNRe0MfyPcCJqD6OTyCiwlplqCr2uFjYztiEDH1uI7SP_ehTR-A"})],
      ["gerhold.co", { data: [{ x: 1 }, { y: 2 }, { z: 3 }] }, %({"protected":"eyJhbGciOiJIUzM4NCJ9","header":{"kid":"gerhold.co"},"signature":"hYN5Iv4bWEVtEukppQDPc4cHWYN9gBzDsgyKgVqi3VheFFCfJG0Jp4Z5ugPuoBub"})],
      ["hoegerrenner.info", { data: [{ x: 1 }, { y: 2 }, { z: 3 }] }, %({"protected":"eyJhbGciOiJSUzM4NCJ9","header":{"kid":"hoegerrenner.info"},"signature":"LjvdPRqVo_RuhYUwVKOk_ZX0eqyYmDKxetzjepqm46oKyK30VUK6srLFzg9WrtQcT777vK7tLRcUSxgIsyNuDJCd7A9yuhkadGkK3NGyGa7lv2JYfIcqrUe6DKTIKvzjsm5u2-mDLdPgUHWt-T8f64ogAnAxdEVmj_zq_wKQwwminq81DSWGxE1hkIivBhtkmJSzjQW-1iA3Bg589mTJP-13L2cjUUMsjpwqj7Yh5fobEVFl7x1b9sodAKrbft0934uPF2QlZta3V8D5XiW2uF9kf-yROjhieF5aAe7ImaV4xtyS03vJaKxaSVy-66PKttqeyZolufqRtKp_DOV2sCi_sE-1SzqHR2dCp-tMAnRI_3QsOFGb6yFJfgjv6634K6DW3hZysz9TEJehKUCYi3MNGLc9LiSLUg9dW4tcb-D0Ds-EpA9QFwOdBxlQ6ane4uzxv4U6YX2Fo5X5PXxadw6tpxIYB_Gm7rPtf7opYJECJVRv1WA4ojIH24GTiQVW"})],
      ["rice.com", { data: [{ x: 1 }, { y: 2 }, { z: 3 }] }, %({"protected":"eyJhbGciOiJIUzUxMiJ9","header":{"kid":"rice.com"},"signature":"68LWv4eb_m57prEo4pqcFwAVjW9seU6nhIFFduxyPxG8hD2UFVYNl3Da_xMGji--yVPQCp05JOQriAsu3zw7pQ"})]
    ].shuffle.each { |args| example(*args) }
  end

private

  def example(signer, payload, expected)
    # Pass instance of OpenSSL::PKey::PKey.
    returned = JWT::Multisig.generate_jws(payload, signer, keys.fetch(signer), algorithms.fetch(signer))
    assert_equal expected, JSON.dump(returned)

    # Pass key in PEM format.
    returned = JWT::Multisig.generate_jws(payload, signer, keys.fetch(signer).to_pem, algorithms.fetch(signer))
    assert_equal expected, JSON.dump(returned)
  end
end
