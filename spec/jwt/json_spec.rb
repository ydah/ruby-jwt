# frozen_string_literal: true

RSpec.describe JWT::JSON do
  describe '.generate' do
    it 'generates JSON from a hash' do
      expect(described_class.generate({ 'a' => 1 })).to eq('{"a":1}')
    end
  end

  describe '.parse' do
    context 'with allow_duplicate_keys: true (default)' do
      it 'uses the last value for duplicate keys' do
        result = described_class.parse('{"a":1,"a":2}')
        expect(result['a']).to eq(2)
      end

      it 'parses valid JSON without duplicates' do
        result = described_class.parse('{"a":1,"b":2}')
        expect(result).to eq({ 'a' => 1, 'b' => 2 })
      end
    end

    context 'with allow_duplicate_keys: false' do
      it 'raises DuplicateKeyError for duplicate keys' do
        expect do
          described_class.parse('{"a":1,"a":2}', allow_duplicate_keys: false)
        end.to raise_error(JWT::DuplicateKeyError, /Duplicate key detected: a/)
      end

      it 'parses valid JSON without duplicates' do
        result = described_class.parse('{"a":1,"b":2}', allow_duplicate_keys: false)
        expect(result).to eq({ 'a' => 1, 'b' => 2 })
      end

      it 'detects duplicates in nested objects' do
        json = '{"outer":{"inner":1,"inner":2}}'
        expect do
          described_class.parse(json, allow_duplicate_keys: false)
        end.to raise_error(JWT::DuplicateKeyError, /Duplicate key detected: inner/)
      end

      it 'allows same key in different objects' do
        json = '{"obj1":{"a":1},"obj2":{"a":2}}'
        result = described_class.parse(json, allow_duplicate_keys: false)
        expect(result['obj1']['a']).to eq(1)
        expect(result['obj2']['a']).to eq(2)
      end
    end
  end
end
