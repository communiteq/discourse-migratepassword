# frozen_string_literal: true

require_relative "../../../lib/phpbb_normalizer"
tables = MigratePassword::PhpbbNormalizer::TABLES.values
interesting =
  tables
    .flat_map do |t|
      t["decomposition"].keys + t["decomposition"].values +
        t["composition"].keys + t["combining_class"].keys
    end
    .uniq
# Every scalar plus exhaustive known compositions/decompositions and ordered/reordered combining pairs.
File.open(File.join(ARGV.fetch(0), "normalization-input.jsonl"), "w") do |f|
  (0..0x10ffff).each do |cp|
    next if (0xd800..0xdfff).cover?(cp)
    f.puts JSON.generate(cp.chr(Encoding::UTF_8))
  end
  interesting.each { |s| f.puts JSON.generate(s) }
  combining = tables.flat_map { |t| t["combining_class"].keys }.uniq
  combining.each do |a|
    combining.each { |b| f.puts JSON.generate("a" + a + b) }
  end
  # Hangul composition is algorithmic, so these sequences are absent from the tables.
  # Include U+11A7 (TBase), adjacent boundaries, and a following Jamo after consumption.
  trailing = (0x11a6..0x11c3).map { |cp| cp.chr(Encoding::UTF_8) }
  suffixes = [""] + trailing + ["a", "\u0301", "\u1100", "\u1161"]
  (0x1100..0x1112).each do |leading|
    (0x1161..0x1175).each do |vowel|
      decomposed = [leading, vowel].pack("U*")
      syllable =
        (0xac00 + ((leading - 0x1100) * 21 + vowel - 0x1161) * 28).chr(
          Encoding::UTF_8
        )
      [decomposed, syllable].each do |prefix|
        trailing.each do |first_trailing|
          suffixes.each do |suffix|
            f.puts JSON.generate(prefix + first_trailing + suffix)
          end
        end
      end
    end
  end
  # Blocked composition and trailing-Jamo sequences after every precomposed syllable.
  (0xac00..0xd7a3).each do |cp|
    syllable = cp.chr(Encoding::UTF_8)
    [
      "\u11a7",
      "\u11a8",
      "\u11a7\u11a8",
      "\u0301\u11a7",
      "\u0301\u11a8"
    ].each { |suffix| f.puts JSON.generate(syllable + suffix) }
  end
  random = Random.new(2_601_030)
  10_000.times do
    f.puts JSON.generate(
             Array
               .new(random.rand(2..8)) { interesting.sample(random: random) }
               .join
           )
  end
end
