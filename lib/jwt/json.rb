# frozen_string_literal: true

require 'json'

module JWT
  # JSON parsing utilities with duplicate key detection support
  # @api private
  class JSON
    class << self
      # Generates a JSON string from the given data
      # @param data [Object] the data to serialize
      # @return [String] the JSON string
      def generate(data)
        ::JSON.generate(data)
      end

      # Parses a JSON string with optional duplicate key detection
      #
      # @param data [String] the JSON string to parse
      # @param allow_duplicate_keys [Boolean] whether to allow duplicate keys (default: true)
      # @return [Hash] the parsed JSON object
      # @raise [JWT::DuplicateKeyError] if allow_duplicate_keys is false and duplicate keys are found
      #
      # @example Default behavior (allows duplicates, uses last value)
      #   JWT::JSON.parse('{"a":1,"a":2}') # => {"a" => 2}
      #
      # @example Strict mode (rejects duplicates)
      #   JWT::JSON.parse('{"a":1,"a":2}', allow_duplicate_keys: false)
      #   # => raises JWT::DuplicateKeyError
      def parse(data, allow_duplicate_keys: true)
        ::JSON.parse(data, allow_duplicate_key: allow_duplicate_keys)
      rescue ::JSON::ParserError => e
        raise JWT::DuplicateKeyError, e.message if e.message.include?('duplicate key')

        raise
      end
    end
  end
end
