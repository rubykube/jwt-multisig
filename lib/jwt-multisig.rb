# encoding: UTF-8
# frozen_string_literal: true

require "jwt"
require "openssl"

module JWT
  module Multisig
    class << self
      def generate_jwt(payload, keychain, algorithms)
        proxy_exception JWT::EncodeError do
          { payload:    payload,
            signatures: keychain.map { |id, value| generate_jws(payload, id, value, algorithms.fetch(id)) } }
        end
      end

      def verify_jwt(jwt, public_keychain, options = {})
        proxy_exception JWT::DecodeError do
          jwt.fetch("signatures").each do |jws|
            verify_jws(jws, jws.fetch("payload"), public_keychain, options)
          end
          JSON.parse(jwt.fetch("payload"))
        end
      end

      # {
      #   "protected":"eyJhbGciOiJFUzI1NiJ9",
      #   "header":{
      #     "kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"
      #   },
      #   "signature":"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
      # }
      def generate_jws(payload, key_id, key_value, algorithm)
        proxy_exception JWT::EncodeError do
          protected, _, signature = JWT.encode(payload, prepare(key_value, algorithm), algorithm).split(".")
          { protected: protected,
            header:    { kid: key_id },
            signature: signature }
        end
      end

      def verify_jws(jws, payload, public_keychain, options = {})
        proxy_exception JWT::DecodeError do
          encoded_header     = jws.fetch("protected")
          serialized_header  = base64_decode(encoded_header)
          serialized_payload = payload.to_json
          encoded_payload    = base64_encode(serialized_payload)
          signature          = jws.fetch("signature")
          public_key         = public_keychain.fetch(jws.fetch("header").fetch("kid"))
          jwt                = [encoded_header, encoded_payload, signature].join(".")
          algorithm          = JSON.load(serialized_header).fetch("alg")
          JWT.decode(jwt, prepare(public_key, algorithm), true, options.merge(algorithms: [algorithm])).first
        end
      end

    private

      def proxy_exception(exception_class)
        yield
      rescue => e
        exception_class === e ? raise(e) : raise(exception_class, e.inspect)
      end

      def prepare(key, algorithm)
        if algorithm.start_with?("HS")
          OpenSSL::PKey::PKey === key ? key.to_pem : key
        else
          OpenSSL::PKey::PKey === key ? key : OpenSSL::PKey.read(key)
        end
      end

      def base64_encode(x)
        JWT::Encode.base64url_encode(x)
      end

      def base64_decode(x)
        JWT::Decode.base64url_decode(x)
      end
    end
  end
end
