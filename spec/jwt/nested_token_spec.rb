# frozen_string_literal: true

RSpec.describe JWT::NestedToken do
  let(:inner_secret) { 'inner_secret_key' }
  let(:outer_secret) { 'outer_secret_key' }
  let(:inner_payload) { { 'user_id' => 123, 'role' => 'admin' } }

  describe '.sign' do
    context 'with HMAC algorithms' do
      let(:inner_jwt) { JWT.encode(inner_payload, inner_secret, 'HS256') }

      it 'creates a nested JWT with cty header set to JWT (NEST-01, NEST-02)' do
        nested_jwt = described_class.sign(inner_jwt, algorithm: 'HS256', key: outer_secret)

        outer_token = JWT::EncodedToken.new(nested_jwt)
        expect(outer_token.header['cty']).to eq('JWT')
        expect(outer_token.header['alg']).to eq('HS256')
      end

      it 'preserves the inner JWT as the payload (NEST-01)' do
        nested_jwt = described_class.sign(inner_jwt, algorithm: 'HS256', key: outer_secret)

        outer_token = JWT::EncodedToken.new(nested_jwt)
        outer_token.verify_signature!(algorithm: 'HS256', key: outer_secret)
        expect(outer_token.unverified_payload).to eq(inner_jwt)
      end

      it 'allows additional header fields (NEST-02)' do
        nested_jwt = described_class.sign(
          inner_jwt,
          algorithm: 'HS256',
          key: outer_secret,
          header: { 'kid' => 'my-key-id' }
        )

        outer_token = JWT::EncodedToken.new(nested_jwt)
        expect(outer_token.header['kid']).to eq('my-key-id')
        expect(outer_token.header['cty']).to eq('JWT')
      end
    end

    context 'with RSA algorithm' do
      let(:rsa_private) { test_pkey('rsa-2048-private.pem') }
      let(:rsa_public) { rsa_private.public_key }
      let(:inner_jwt) { JWT.encode(inner_payload, inner_secret, 'HS256') }

      it 'creates a nested JWT signed with RSA' do
        nested_jwt = described_class.sign(inner_jwt, algorithm: 'RS256', key: rsa_private)

        outer_token = JWT::EncodedToken.new(nested_jwt)
        expect(outer_token.header['alg']).to eq('RS256')
        expect(outer_token.header['cty']).to eq('JWT')

        outer_token.verify_signature!(algorithm: 'RS256', key: rsa_public)
        expect(outer_token.unverified_payload).to eq(inner_jwt)
      end
    end
  end

  describe '.decode' do
    let(:inner_jwt) { JWT.encode(inner_payload, inner_secret, 'HS256') }
    let(:nested_jwt) { described_class.sign(inner_jwt, algorithm: 'HS256', key: outer_secret) }

    it 'decodes a nested JWT and returns all levels (NEST-03)' do
      tokens = described_class.decode(
        nested_jwt,
        keys: [
          { algorithm: 'HS256', key: outer_secret },
          { algorithm: 'HS256', key: inner_secret }
        ]
      )

      expect(tokens.length).to eq(2)
      expect(tokens.first.header['cty']).to eq('JWT')
      expect(tokens.last.payload).to eq(inner_payload)
    end

    it 'handles case-insensitive cty header values (NEST-04)' do
      token = JWT::Token.new(payload: inner_jwt, header: { 'cty' => 'jwt' })
      token.sign!(algorithm: 'HS256', key: outer_secret)
      nested_jwt_lowercase = token.jwt

      tokens = described_class.decode(
        nested_jwt_lowercase,
        keys: [
          { algorithm: 'HS256', key: outer_secret },
          { algorithm: 'HS256', key: inner_secret }
        ]
      )

      expect(tokens.length).to eq(2)
      expect(tokens.last.payload).to eq(inner_payload)
    end

    it 'supports multiple nesting levels (NEST-05)' do
      level_1_jwt = JWT.encode(inner_payload, 'secret_1', 'HS256')
      level_2_jwt = described_class.sign(level_1_jwt, algorithm: 'HS384', key: 'secret_2')
      level_3_jwt = described_class.sign(level_2_jwt, algorithm: 'HS512', key: 'secret_3')

      tokens = described_class.decode(
        level_3_jwt,
        keys: [
          { algorithm: 'HS512', key: 'secret_3' },
          { algorithm: 'HS384', key: 'secret_2' },
          { algorithm: 'HS256', key: 'secret_1' }
        ]
      )

      expect(tokens.length).to eq(3)
      expect(tokens[0].header['alg']).to eq('HS512')
      expect(tokens[1].header['alg']).to eq('HS384')
      expect(tokens[2].header['alg']).to eq('HS256')
      expect(tokens.last.payload).to eq(inner_payload)
    end

    it 'verifies signatures at each nesting level (NEST-06)' do
      tokens = described_class.decode(
        nested_jwt,
        keys: [
          { algorithm: 'HS256', key: outer_secret },
          { algorithm: 'HS256', key: inner_secret }
        ]
      )

      tokens.each do |token|
        expect { token.payload }.not_to raise_error
      end
    end

    it 'raises an error if outer signature verification fails (NEST-06)' do
      expect do
        described_class.decode(
          nested_jwt,
          keys: [
            { algorithm: 'HS256', key: 'wrong_key' },
            { algorithm: 'HS256', key: inner_secret }
          ]
        )
      end.to raise_error(JWT::VerificationError, 'Signature verification failed')
    end

    it 'raises an error if inner signature verification fails (NEST-06)' do
      expect do
        described_class.decode(
          nested_jwt,
          keys: [
            { algorithm: 'HS256', key: outer_secret },
            { algorithm: 'HS256', key: 'wrong_key' }
          ]
        )
      end.to raise_error(JWT::VerificationError, 'Signature verification failed')
    end

    it 'raises DecodeError when non-nested token has more keys provided' do
      simple_jwt = JWT.encode(inner_payload, inner_secret, 'HS256')

      expect do
        described_class.decode(
          simple_jwt,
          keys: [
            { algorithm: 'HS256', key: inner_secret },
            { algorithm: 'HS256', key: 'extra_key' }
          ]
        )
      end.to raise_error(JWT::DecodeError, 'Token is not nested but more keys were provided')
    end

    context 'with different algorithms at each level' do
      let(:rsa_private) { test_pkey('rsa-2048-private.pem') }
      let(:rsa_public) { rsa_private.public_key }

      it 'supports HS256 inner with RS256 outer' do
        inner_jwt = JWT.encode(inner_payload, inner_secret, 'HS256')
        nested_jwt = described_class.sign(inner_jwt, algorithm: 'RS256', key: rsa_private)

        tokens = described_class.decode(
          nested_jwt,
          keys: [
            { algorithm: 'RS256', key: rsa_public },
            { algorithm: 'HS256', key: inner_secret }
          ]
        )

        expect(tokens.length).to eq(2)
        expect(tokens.first.header['alg']).to eq('RS256')
        expect(tokens.last.header['alg']).to eq('HS256')
        expect(tokens.last.payload).to eq(inner_payload)
      end

      it 'supports RS256 inner with HS256 outer' do
        inner_jwt = JWT.encode(inner_payload, rsa_private, 'RS256')
        nested_jwt = described_class.sign(inner_jwt, algorithm: 'HS256', key: outer_secret)

        tokens = described_class.decode(
          nested_jwt,
          keys: [
            { algorithm: 'HS256', key: outer_secret },
            { algorithm: 'RS256', key: rsa_public }
          ]
        )

        expect(tokens.length).to eq(2)
        expect(tokens.first.header['alg']).to eq('HS256')
        expect(tokens.last.header['alg']).to eq('RS256')
        expect(tokens.last.payload).to eq(inner_payload)
      end
    end
  end
end
