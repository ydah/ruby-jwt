# frozen_string_literal: true

RSpec.describe 'Duplicate Claim Name Detection' do
  let(:secret) { 'test_secret' }
  let(:algorithm) { 'HS256' }

  def sign_jwt(signing_input, secret)
    signature = OpenSSL::HMAC.digest('SHA256', secret, signing_input)
    JWT::Base64.url_encode(signature)
  end

  def build_jwt_with_duplicate_payload(duplicate_payload_json)
    header = JWT::Base64.url_encode('{"alg":"HS256"}')
    payload = JWT::Base64.url_encode(duplicate_payload_json)
    signing_input = "#{header}.#{payload}"
    signature = sign_jwt(signing_input, secret)
    "#{signing_input}.#{signature}"
  end

  def build_jwt_with_duplicate_header(duplicate_header_json, payload_json = '{"sub":"user"}')
    header = JWT::Base64.url_encode(duplicate_header_json)
    payload = JWT::Base64.url_encode(payload_json)
    signing_input = "#{header}.#{payload}"
    signature = sign_jwt(signing_input, secret)
    "#{signing_input}.#{signature}"
  end

  describe 'payload with duplicate keys' do
    let(:duplicate_payload_jwt) { build_jwt_with_duplicate_payload('{"sub":"user","sub":"admin"}') }

    context 'with default configuration' do
      it 'uses the last value (backward compatible)' do
        payload, = JWT.decode(duplicate_payload_jwt, secret, true, algorithm: algorithm)
        expect(payload['sub']).to eq('admin')
      end
    end

    context 'with allow_duplicate_keys: true' do
      it 'uses the last value' do
        payload, = JWT.decode(duplicate_payload_jwt, secret, true, algorithm: algorithm, allow_duplicate_keys: true)
        expect(payload['sub']).to eq('admin')
      end
    end

    context 'with allow_duplicate_keys: false' do
      it 'raises DuplicateKeyError' do
        expect do
          JWT.decode(duplicate_payload_jwt, secret, true, algorithm: algorithm, allow_duplicate_keys: false)
        end.to raise_error(JWT::DuplicateKeyError, /Duplicate key detected: sub/)
      end
    end
  end

  describe 'header with duplicate keys' do
    let(:duplicate_header_jwt) { build_jwt_with_duplicate_header('{"alg":"HS256","alg":"none"}') }

    context 'with default configuration' do
      it 'uses the last value (backward compatible)' do
        _, header = JWT.decode(duplicate_header_jwt, nil, false)
        expect(header['alg']).to eq('none')
      end
    end

    context 'with allow_duplicate_keys: false' do
      it 'raises DuplicateKeyError for header' do
        expect do
          JWT.decode(duplicate_header_jwt, nil, false, allow_duplicate_keys: false)
        end.to raise_error(JWT::DuplicateKeyError, /Duplicate key detected: alg/)
      end
    end
  end

  describe 'global configuration' do
    around do |example|
      original = JWT.configuration.decode.allow_duplicate_keys
      example.run
      JWT.configuration.decode.allow_duplicate_keys = original
    end

    let(:duplicate_payload_jwt) { build_jwt_with_duplicate_payload('{"sub":"user","sub":"admin"}') }

    it 'respects global configuration when set to false' do
      JWT.configuration.decode.allow_duplicate_keys = false

      expect do
        JWT.decode(duplicate_payload_jwt, secret, true, algorithm: algorithm)
      end.to raise_error(JWT::DuplicateKeyError)
    end

    it 'allows per-decode override of global configuration' do
      JWT.configuration.decode.allow_duplicate_keys = false

      payload, = JWT.decode(
        duplicate_payload_jwt,
        secret,
        true,
        algorithm: algorithm,
        allow_duplicate_keys: true
      )
      expect(payload['sub']).to eq('admin')
    end

    it 'defaults to allowing duplicate keys' do
      expect(JWT.configuration.decode.allow_duplicate_keys).to be(true)
    end
  end

  describe 'multiple duplicate keys' do
    let(:multiple_duplicates_jwt) { build_jwt_with_duplicate_payload('{"a":1,"b":2,"a":3,"b":4}') }

    context 'with allow_duplicate_keys: false' do
      it 'raises DuplicateKeyError for the first duplicate found' do
        expect do
          JWT.decode(multiple_duplicates_jwt, secret, true, algorithm: algorithm, allow_duplicate_keys: false)
        end.to raise_error(JWT::DuplicateKeyError, /Duplicate key detected: a/)
      end
    end
  end
end
