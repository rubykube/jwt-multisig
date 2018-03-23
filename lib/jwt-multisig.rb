# encoding: UTF-8
# frozen_string_literal: true

require "jwt"
require "openssl"

module JWT
  module Multisig
    class << self
      def encode(payload, keychain, algorithms)
        { payload:    payload,
          signatures: keychain.map { |id, value| generate_jws(payload, id, value, algorithms.fetch(id)) } }
      rescue => e
        JWT::EncodeError === e ? raise(e) : raise(JWT::EncodeError, e.inspect)
      end

      def decode(jwt, public_keychain, token_verification_options = {})
        jwt.fetch('signatures').each do |jws|
          verify_jws!(jws, public_keychain, jws.fetch('payload'), token_verification_options)
        end
        JSON.parse(jwt.fetch('payload'))
      end

      # {
      #   "protected":"eyJhbGciOiJFUzI1NiJ9",
      #   "header":{
      #     "kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"
      #   },
      #   "signature":"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
      # }
      def generate_jws(payload, key_id, key_value, algorithm)
        # binding.pry

        key = if algorithm.start_with?('HS')
          OpenSSL::PKey === key_value ? key_value.to_pem : key_value
        else
          OpenSSL::PKey === key_value ? key_value : OpenSSL::PKey.read(key_value)
        end

        protected, _, signature = JWT.encode(payload, key, algorithm).split(".")
        { protected: protected,
          header:    { kid: key_id },
          signature: signature }
      end

      def verify_jws!(jws_hash, public_keychain, encoded_payload, token_verification_options)
        header     = jws_hash.fetch('protected')
        payload    = encoded_payload
        signature  = jws_hash.fetch('signature')
        public_key = public_keychain.fetch(jws_hash.fetch('header').fetch('kid'))
        jwt        = [header, payload, signature]
        JWT.decode(jwt, public_key, true, token_verification_options.merge(algorithms: JSON.load(header).fetch('alg')))
      end
    end
  end
end
