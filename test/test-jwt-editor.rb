# encoding: UTF-8
# frozen_string_literal: true

require_relative "test-helper"

class JWTEditorTest < Test::Unit::TestCase
  def test_add_jws
    jwt        = JSON.parse(%{{"payload":"eyJmb28iOjEsImJhciI6MiwiYmF6IjozfQ","signatures":[{"protected":"eyJhbGciOiJSUzI1NiJ9","header":{"kid":"powlowski.info"},"signature":"SHGndP6B-pk7qF6AQTpvlqPpFI8FzidpM-bzYlVp-6_5Ti8kabbordJtgMDt6d03WdcTVdYXd_FQTfBUyASNvTj3EPxpRgbosxEAyu2nb909WgxWM0xusMxDWlUmNx4Q1dbrlBUmfxVjCWbKcfmGqbIFN7SYUvbi-ScIpXWK3dtImbp3OKYNdpDY-MqSX2dN8_v73LJD66fYne1F5AOsYmzucnYmHggqWZymqVGwRUluG5VWdXFWSwavVBfZGQLE05l1WiwU5HoxgS8BiuPX8nohgHUbQym1kOQHgvXHvnhGTg-rKYjisdDEqv6Ol5soWBEPmYkKhepkp0SXCG5bLiZMIn-dhN1hPZmcn9Iwp3gUTQQx-PBB04LXJghpBAhsFG54cKm_kdiCo1vf9bMEhIl2cbaNrbITU0cZ27947gJCuguXcuw2Fts80TNgZLg5abmt5MXOErK7C85ABZ3WxFlcXaIIy-2msoFg7Q5YRUIUZcODSMcswnrgQy5bqq57vzA5Wx3b6nuYPo7dLPquIVnHDSDK5sNf0V1muLKqLWArPveMBx6GZxxH8j-EB7VnkoilrzMOay-s9z0uKFYYAPLfXjD2Bh-iS8-0mXmsQ8Kigf1fJIG4QFu-PLs4_7xA_mqo-GstshpzThXZpqfVwLMBCgNBhKysJrzbHF5f48g"},{"protected":"eyJhbGciOiJSUzM4NCJ9","header":{"kid":"hoegerrenner.info"},"signature":"LalThItuDiAsEfWSy1sbAXggtq4w0P9ptgeUmtj75jDgrTevLrCRWBux5sgcwQUKDB1Ap6yYXaPDHGgDm_20AhpWOBgKijp5mIsG542G7n_hVuu3siaX4yN4DoY4OOWmeGduiP1w_M_Da53xajBqBJcgj9Zs090xFnewUAsv11n8Yk2DKrP2nKfhyaF210-cCDcZCjiUNF2uwxaYjosG5ijFXEadxcqNfuxc2Qzk2Qt47dYhN1pL1--sHl0EyjLZIrC1zRJxN7vLv0BG4adoGq5fxVbKcqfV2v9DIloxjP4O7HcRVkPXdfv764ZhrfY8w3HWR85j8j5NGE6lRug-DtGy8R7Y0FhLadJMa9i4G0fRq11soVyNoIs3-zBgpp23m4_FWI5AirF00HODC1Jg2E1Nhjx5Mf9SB6RpVHLE0D7EgkAgr9KQqCrPJF-uP5U3ADLK7zu7bts0pBKZCA-dfnVKXKkEP7h0s3RXx4awTjeDfdIvJpS-Y2SGKHgGsvir"}]}})
    new_signer = "ebert.biz"
    2.times do
      new_jwt = JWT::Multisig.add_jws(jwt, new_signer, private_keychain.fetch(new_signer), algorithms.fetch(new_signer))
      assert_equal %({"payload":"eyJmb28iOjEsImJhciI6MiwiYmF6IjozfQ","signatures":[{"protected":"eyJhbGciOiJSUzI1NiJ9","header":{"kid":"powlowski.info"},"signature":"SHGndP6B-pk7qF6AQTpvlqPpFI8FzidpM-bzYlVp-6_5Ti8kabbordJtgMDt6d03WdcTVdYXd_FQTfBUyASNvTj3EPxpRgbosxEAyu2nb909WgxWM0xusMxDWlUmNx4Q1dbrlBUmfxVjCWbKcfmGqbIFN7SYUvbi-ScIpXWK3dtImbp3OKYNdpDY-MqSX2dN8_v73LJD66fYne1F5AOsYmzucnYmHggqWZymqVGwRUluG5VWdXFWSwavVBfZGQLE05l1WiwU5HoxgS8BiuPX8nohgHUbQym1kOQHgvXHvnhGTg-rKYjisdDEqv6Ol5soWBEPmYkKhepkp0SXCG5bLiZMIn-dhN1hPZmcn9Iwp3gUTQQx-PBB04LXJghpBAhsFG54cKm_kdiCo1vf9bMEhIl2cbaNrbITU0cZ27947gJCuguXcuw2Fts80TNgZLg5abmt5MXOErK7C85ABZ3WxFlcXaIIy-2msoFg7Q5YRUIUZcODSMcswnrgQy5bqq57vzA5Wx3b6nuYPo7dLPquIVnHDSDK5sNf0V1muLKqLWArPveMBx6GZxxH8j-EB7VnkoilrzMOay-s9z0uKFYYAPLfXjD2Bh-iS8-0mXmsQ8Kigf1fJIG4QFu-PLs4_7xA_mqo-GstshpzThXZpqfVwLMBCgNBhKysJrzbHF5f48g"},{"protected":"eyJhbGciOiJSUzM4NCJ9","header":{"kid":"hoegerrenner.info"},"signature":"LalThItuDiAsEfWSy1sbAXggtq4w0P9ptgeUmtj75jDgrTevLrCRWBux5sgcwQUKDB1Ap6yYXaPDHGgDm_20AhpWOBgKijp5mIsG542G7n_hVuu3siaX4yN4DoY4OOWmeGduiP1w_M_Da53xajBqBJcgj9Zs090xFnewUAsv11n8Yk2DKrP2nKfhyaF210-cCDcZCjiUNF2uwxaYjosG5ijFXEadxcqNfuxc2Qzk2Qt47dYhN1pL1--sHl0EyjLZIrC1zRJxN7vLv0BG4adoGq5fxVbKcqfV2v9DIloxjP4O7HcRVkPXdfv764ZhrfY8w3HWR85j8j5NGE6lRug-DtGy8R7Y0FhLadJMa9i4G0fRq11soVyNoIs3-zBgpp23m4_FWI5AirF00HODC1Jg2E1Nhjx5Mf9SB6RpVHLE0D7EgkAgr9KQqCrPJF-uP5U3ADLK7zu7bts0pBKZCA-dfnVKXKkEP7h0s3RXx4awTjeDfdIvJpS-Y2SGKHgGsvir"},{"protected":"eyJhbGciOiJIUzUxMiJ9","header":{"kid":"ebert.biz"},"signature":"qD-u3ioPpLvrG-lMojA_ceLUUT0F3oYuK-Tuh7K5PWbSkxuCQqwiiK4Jqlur2QzNc6vkHWtwlZSH8wwhGVAQ3Q"}]}), new_jwt.to_json
    end
  end

  def test_remove_jws
    jwt = JSON.parse(%({"payload":"eyJpc3MiOiJteWNvbXBhbnkuZXhhbXBsZSIsImRhdGEiOlsxLDIsM119","signatures":[{"protected":"eyJhbGciOiJIUzI1NiJ9","header":{"kid":"mcglynn.org"},"signature":"3hBmZPpW0IsfSIuJNb3H8-6cKJ2V5PiCmcaKLoIah0M"}]}))
    2.times do
      new_jwt = JWT::Multisig.remove_jws(jwt, "mcglynn.org")
      assert_equal %({"payload":"eyJpc3MiOiJteWNvbXBhbnkuZXhhbXBsZSIsImRhdGEiOlsxLDIsM119","signatures":[]}), new_jwt.to_json
    end
  end

  def test_remove_jws_when_no_jws_exist
    jwt     = JSON.parse(%({"payload":"eyJxdXgiOiJxdXgifQ"}))
    new_jwt = JWT::Multisig.remove_jws(jwt, "olsonjacobi.name")
    assert_equal %({"payload":"eyJxdXgiOiJxdXgifQ","signatures":[]}), new_jwt.to_json
  end
end
