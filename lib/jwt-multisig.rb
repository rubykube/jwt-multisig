# encoding: UTF-8
# frozen_string_literal: true

require "jwt"
require "openssl"

module JWT
  #
  # The module provides tools for encoding/decoding JWT with multiple signatures.
  #
  module Multisig
    class << self
      #
      # Generates new JWT based on payload, keys, and algorithms.
      #
      # @param payload [Hash]
      # @param private_keychain [Hash]
      #   The hash which consists of pairs: key ID => private key.
      #   The key may be presented as string in PEM format or as instance of {OpenSSL::PKey::PKey}.
      # @param algorithms
      #   The hash which consists of pairs: key ID => signature algorithm.
      # @return [Hash]
      #   The JWT in the format as defined in RFC 7515.
      #   Example:
      #     { payload: "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
      #       signatures: [
      #         { protected: "eyJhbGciOiJSUzI1NiJ9",
      #           header: { kid: "2010-12-29" },
      #           signature: "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"
      #         },
      #         { protected: "eyJhbGciOiJFUzI1NiJ9",
      #           header: { kid: "e9bc097a-ce51-4036-9562-d2ade882db0d" },
      #           signature: "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
      #         }
      #       ]
      #     }
      # @raise [JWT::EncodeError]
      def generate_jwt(payload, private_keychain, algorithms)
        proxy_exception JWT::EncodeError do
          { payload:    base64_encode(payload.to_json),
            signatures: private_keychain.map { |id, value| generate_jws(payload, id, value, algorithms.fetch(id)) } }
        end
      end

      #
      # Verifies JWT.
      #
      # @param jwt [Hash]
      #   The JWT in the format as defined in RFC 7515.
      #   Example:
      #     { "payload" => "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
      #       "signatures" => [
      #         { "protected" => "eyJhbGciOiJSUzI1NiJ9",
      #           "header" => { "kid" => "2010-12-29" },
      #           "signature" => "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"
      #         },
      #         { "protected" => "eyJhbGciOiJFUzI1NiJ9",
      #           "header" => { "kid" => "e9bc097a-ce51-4036-9562-d2ade882db0d" },
      #           "signature" => "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
      #         }
      #       ]
      #     }
      # @param public_keychain [Hash]
      #   The hash which consists of pairs: key ID => public key.
      #   The key may be presented as string in PEM format or as instance of {OpenSSL::PKey::PKey}
      # @param options [Hash]
      #   The rules for verifying JWT. The variable «algorithms» is always overwritten by the value from JWS header.
      # @return [Hash]
      #   Returns payload if all signatures are valid.
      # @raise [JWT::DecodeError]
      def verify_jwt(jwt, public_keychain, options = {})
        proxy_exception JWT::DecodeError do
          jwt.fetch("signatures").each do |jws|
            verify_jws(jws, jws.fetch("payload"), public_keychain, options)
          end
          JSON.parse(jwt.fetch("payload"))
        end
      end

      #
      # Generates new JWS based on payload, key, and algorithm.
      #
      # @param payload [Hash]
      # @param key_id [String]
      #   The value which is used as «kid» in JWS header.
      # @param key_value [String, OpenSSL::PKey::PKey]
      #   The private key.
      # @param algorithm [String]
      #   The signature algorithm.
      # @return [Hash]
      #   The JWS in the format as defined in RFC 7515.
      #   Example:
      #     { protected: "eyJhbGciOiJFUzI1NiJ9",
      #       header: {
      #         kid: "e9bc097a-ce51-4036-9562-d2ade882db0d"
      #       },
      #       signature: "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
      #     }
      # @raise [JWT::EncodeError]
      def generate_jws(payload, key_id, key_value, algorithm)
        proxy_exception JWT::EncodeError do
          protected, _, signature = JWT.encode(payload, prepare(key_value, algorithm), algorithm).split(".")
          { protected: protected,
            header:    { kid: key_id },
            signature: signature }
        end
      end

      #
      # Verifies JWS.
      #
      # @param jws [Hash]
      #   The JWS in the format as defined in RFC 7515.
      #   Example:
      #     { "protected" => "eyJhbGciOiJFUzI1NiJ9",
      #       "header" => {
      #         "kid" => "e9bc097a-ce51-4036-9562-d2ade882db0d"
      #       },
      #       "signature" => "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
      #     }
      # @param payload [Hash]
      # @param public_keychain [Hash]
      #   The hash which consists of pairs: key ID => public key.
      #   The key may be presented as string in PEM format or as instance of {OpenSSL::PKey::PKey}
      # @param options [Hash]
      #   The rules for verifying JWT. The variable «algorithms» is always overwritten by the value from JWS header.
      # @return [Hash]
      #   Returns payload if signature is valid.
      # @raise [JWT::DecodeError]
      def verify_jws(jws, payload, public_keychain, options = {})
        proxy_exception JWT::DecodeError do
          encoded_header     = jws.fetch("protected")
          serialized_header  = base64_decode(encoded_header)
          serialized_payload = payload.to_json
          encoded_payload    = base64_encode(serialized_payload)
          signature          = jws.fetch("signature")
          public_key         = public_keychain.fetch(jws.fetch("header").fetch("kid"))
          jwt                = [encoded_header, encoded_payload, signature].join(".")
          algorithm          = JSON.parse(serialized_header).fetch("alg")
          JWT.decode(jwt, prepare(public_key, algorithm), true, options.merge(algorithms: [algorithm])).first
        end
      end

    private

      def proxy_exception(exception_class)
        yield
      rescue StandardError => e
        exception_class === e ? raise(e) : raise(exception_class, e.inspect)
      end

      def prepare(key, algorithm)
        if algorithm.start_with?("HS")
          OpenSSL::PKey::PKey === key ? key.to_pem : key
        else
          OpenSSL::PKey::PKey === key ? key : OpenSSL::PKey.read(key)
        end
      end

      def base64_encode(string)
        JWT::Encode.base64url_encode(string)
      end

      def base64_decode(string)
        JWT::Decode.base64url_decode(string)
      end
    end
  end
end
