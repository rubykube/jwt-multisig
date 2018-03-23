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
          jwt.fetch('signatures').each do |jws|
            verify_jws(jws, public_keychain, jws.fetch('payload'), options)
          end
          JSON.parse(jwt.fetch('payload'))
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
          key = if algorithm.start_with?('HS')
            OpenSSL::PKey::PKey === key_value ? key_value.to_pem : key_value
          else
            OpenSSL::PKey::PKey === key_value ? key_value : OpenSSL::PKey.read(key_value)
          end
  
          protected, _, signature = JWT.encode(payload, key, algorithm).split(".")
          { protected: protected,
            header:    { kid: key_id },
            signature: signature }
        end
      end

      def verify_jws(jws, public_keychain, payload, options = {})
        proxy_exception JWT::DecodeError do
          serialized_header  = jws.fetch('protected')
          serialized_payload = payload.to_json
          signature          = jws.fetch('signature')
          public_key         = public_keychain.fetch(jws.fetch('header').fetch('kid'))
          jwt                = [serialized_header, serialized_payload, signature]
          JWT.decode(jwt, public_key, true, options.merge(algorithms: JSON.load(serialized_header).fetch('alg')))
        end
      end

    private

      def proxy_exception(exception_class)
        yield
      rescue => e
        exception_class === e ? raise(e) : raise(exception_class, e.inspect)
      end
    end
  end
end
