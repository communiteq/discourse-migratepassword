# frozen_string_literal: true

require_relative "../../../lib/phpbb_normalizer"
id = ARGV.fetch(1)
mismatches = []
count = 0
File.open(
  File.join(ARGV.fetch(0), "normalization-" + id + ".jsonl")
) do |expected|
  File.foreach(File.join(ARGV.fetch(0), "normalization-input.jsonl")) do |line|
    source = JSON.parse(line)
    result = JSON.parse(expected.readline)
    actual = MigratePassword::PhpbbNormalizer.normalize(source, id)
    if actual != result && mismatches.size < 15
      mismatches << {
        source: source.codepoints,
        expected: result.codepoints,
        actual: actual.codepoints
      }
    end
    count += 1
  end
  abort "Extra expected lines" unless expected.eof?
end
puts "#{id}: #{count} cases; first mismatches: #{mismatches.inspect}"
abort "Normalization mismatch" unless mismatches.empty?
