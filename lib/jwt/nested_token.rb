# frozen_string_literal: true

module JWT
  # Provides functionality for creating and decoding Nested JWTs
  # as defined in RFC 7519 Section 5.2, Section 7.1 Step 5, and Appendix A.2.
  #
  # A Nested JWT is a JWT that is used as the payload of another JWT,
  # allowing for multiple layers of signing or encryption.
  #
  # @example Creating a Nested JWT
  #   inner_jwt = JWT.encode({ user_id: 123 }, 'inner_secret', 'HS256')
  #   nested_jwt = JWT::NestedToken.sign(
  #     inner_jwt,
  #     algorithm: 'RS256',
  #     key: rsa_private_key
  #   )
  #
  # @example Decoding a Nested JWT
  #   tokens = JWT::NestedToken.decode(
  #     nested_jwt,
  #     keys: [
  #       { algorithm: 'RS256', key: rsa_public_key },
  #       { algorithm: 'HS256', key: 'inner_secret' }
  #     ]
  #   )
  #   inner_payload = tokens.last.payload
  #
  # @see https://datatracker.ietf.org/doc/html/rfc7519#section-5.2 RFC 7519 Section 5.2
  class NestedToken
    # The content type header value for nested JWTs as per RFC 7519
    CTY_JWT = 'JWT'

    class << self
      # Wraps an inner JWT with an outer JWS, creating a Nested JWT.
      # Automatically sets the `cty` (content type) header to "JWT" as required by RFC 7519.
      #
      # @param inner_jwt [String] the inner JWT string to wrap
      # @param algorithm [String] the signing algorithm for the outer JWS (e.g., 'RS256', 'HS256')
      # @param key [Object] the signing key for the outer JWS
      # @param header [Hash] additional header fields to include (cty is automatically set)
      # @return [String] the Nested JWT string
      #
      # @raise [JWT::EncodeError] if signing fails
      #
      # @example Basic usage with HS256
      #   inner_jwt = JWT.encode({ sub: 'user' }, 'secret', 'HS256')
      #   nested = JWT::NestedToken.sign(inner_jwt, algorithm: 'HS256', key: 'outer_secret')
      #
      # @example With RSA and custom headers
      #   nested = JWT::NestedToken.sign(
      #     inner_jwt,
      #     algorithm: 'RS256',
      #     key: rsa_private_key,
      #     header: { kid: 'my-key-id' }
      #   )
      def sign(inner_jwt, algorithm:, key:, header: {})
        outer_header = header.merge('cty' => CTY_JWT)
        token = Token.new(payload: inner_jwt, header: outer_header)
        token.sign!(algorithm: algorithm, key: key)
        token.jwt
      end

      # Decodes and verifies a Nested JWT, unwrapping all nesting levels.
      # Each level's signature is verified using the corresponding key configuration.
      #
      # @param token [String] the Nested JWT string to decode
      # @param keys [Array<Hash>] an array of key configurations for each nesting level,
      #   ordered from outermost to innermost. Each hash should contain:
      #   - `:algorithm` [String] the expected algorithm
      #   - `:key` [Object] the verification key
      # @return [Array<JWT::EncodedToken>] array of tokens from outermost to innermost
      #
      # @raise [JWT::DecodeError] if decoding fails at any level
      # @raise [JWT::VerificationError] if signature verification fails at any level
      #
      # @example Decoding a two-level nested JWT
      #   tokens = JWT::NestedToken.decode(
      #     nested_jwt,
      #     keys: [
      #       { algorithm: 'RS256', key: rsa_public_key },
      #       { algorithm: 'HS256', key: 'inner_secret' }
      #     ]
      #   )
      #   inner_token = tokens.last
      #   inner_token.payload # => { 'user_id' => 123 }
      def decode(token, keys:)
        tokens = []
        current_token = token

        keys.each_with_index do |key_config, index|
          encoded_token = EncodedToken.new(current_token)
          encoded_token.verify_signature!(
            algorithm: key_config[:algorithm],
            key: key_config[:key]
          )

          tokens << encoded_token

          if encoded_token.nested?
            current_token = encoded_token.unverified_payload
          elsif index < keys.length - 1
            raise JWT::DecodeError, 'Token is not nested but more keys were provided'
          end
        end

        tokens.each(&:verify_claims!)
        tokens
      end
    end
  end
end
