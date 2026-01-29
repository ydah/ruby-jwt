# frozen_string_literal: true

require 'json'
require 'strscan'

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
        DuplicateKeyChecker.check!(data) unless allow_duplicate_keys
        ::JSON.parse(data)
      end
    end

    # @api private
    # Checks for duplicate keys in a JSON string using a StringScanner-based tokenizer
    # rubocop:disable Style/RedundantRegexpArgument
    class DuplicateKeyChecker
      def self.check!(json_str)
        new(json_str).check!
      end

      def initialize(json_str)
        @scanner = StringScanner.new(json_str)
        @seen_keys_stack = [[]]
        @depth = 0
        @in_array_stack = [false]
      end

      def check!
        scan_tokens until @scanner.eos?
      end

      private

      def scan_tokens # rubocop:disable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
        skip_whitespace
        return if @scanner.eos?

        if @scanner.scan(/\{/)
          handle_object_start
        elsif @scanner.scan(/\}/)
          handle_container_end
        elsif @scanner.scan(/\[/)
          handle_array_start
        elsif @scanner.scan(/\]/)
          @depth -= 1
        elsif @scanner.scan(/,/) || @scanner.scan(/:/)
          # skip comma and colon
        elsif @scanner.scan(/"/)
          handle_string
        elsif @scanner.scan(/-?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/)
          # skip number
        elsif @scanner.scan(/true|false|null/)
          # skip literal
        else
          @scanner.getch
        end
      end

      def skip_whitespace
        @scanner.scan(/\s+/)
      end

      def handle_object_start
        @depth += 1
        @seen_keys_stack[@depth] = []
        @in_array_stack[@depth] = false
      end

      def handle_array_start
        @depth += 1
        @seen_keys_stack[@depth] = []
        @in_array_stack[@depth] = true
      end

      def handle_container_end
        @depth -= 1
      end

      def handle_string
        str = scan_string_content
        check_if_key(str)
      end

      def scan_string_content
        str = +''
        str << (@scanner.getch || '') until @scanner.scan(/"/)
        str
      end

      def check_if_key(str)
        return if @in_array_stack[@depth]

        pos = @scanner.pos
        skip_whitespace
        if @scanner.peek(1) == ':'
          raise JWT::DuplicateKeyError, "Duplicate key detected: #{str}" if @seen_keys_stack[@depth].include?(str)

          @seen_keys_stack[@depth] << str
        end
        @scanner.pos = pos
      end
    end
    # rubocop:enable Style/RedundantRegexpArgument
  end
end
