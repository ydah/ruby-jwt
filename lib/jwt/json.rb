# frozen_string_literal: true

require 'json'

module JWT
  # @api private
  class JSON
    class << self
      def generate(data)
        ::JSON.generate(data)
      end

      def parse(data, allow_duplicate_keys: true)
        return ::JSON.parse(data) if allow_duplicate_keys

        if supports_duplicate_key_detection?
          ::JSON.parse(data, allow_duplicate_key: false)
        else
          ::JSON.parse(data)
        end
      rescue ::JSON::ParserError => e
        raise JWT::DuplicateKeyError, e.message if e.message.include?('duplicate key')

        raise
      end

      private

      def supports_duplicate_key_detection?
        return @supports_duplicate_key_detection if defined?(@supports_duplicate_key_detection)

        @supports_duplicate_key_detection = Gem::Version.new(::JSON::VERSION) >= Gem::Version.new('2.13.0')
      end
    end
  end
end
