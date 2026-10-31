# frozen_string_literal: true

require "json"

module MigratePassword
  # Source-specific NFC tables, independent of the Unicode version in Ruby.
  class PhpbbNormalizer
    TABLES =
      Dir[File.join(__dir__, "phpbb_normalizers/*.json")]
        .to_h do |path|
          data = JSON.parse(File.read(path))
          [data.fetch("id"), data]
        end
        .freeze

    def self.normalize(password, normalizer)
      table = TABLES[normalizer]
      return unless table
      # phpBB's bundled normalizer also replaces these two noncharacters.
      password = password.tr("\uFFFE\uFFFF", "\uFFFD\uFFFD") if normalizer ==
        "phpbb-bundled"
      decomposed =
        password.each_char.flat_map do |char|
          syllable = char.ord - 0xAC00
          if (0...11_172).cover?(syllable) && normalizer != "phpbb-bundled"
            chars = [
              (0x1100 + syllable / 588).chr(Encoding::UTF_8),
              (0x1161 + syllable % 588 / 28).chr(Encoding::UTF_8)
            ]
            unless syllable % 28 == 0
              chars << (0x11A7 + syllable % 28).chr(Encoding::UTF_8)
            end
            chars
          else
            table.fetch("decomposition").fetch(char, char).chars
          end
        end
      classes = table.fetch("combining_class")
      # Canonical order is stable; a class-zero starter is a boundary.
      ordered = []
      decomposed.each do |char|
        current = classes.fetch(char, 0)
        position = ordered.length
        if current > 0
          position -= 1 while position > 0 &&
            classes.fetch(ordered[position - 1], 0) > current
        end
        ordered.insert(position, char)
      end
      result = []
      starter = nil
      previous_class = 0
      consumed_index = nil
      ordered.each_with_index do |char, index|
        next if index == consumed_index
        current = classes.fetch(char, 0)
        composite = nil
        if starter && (previous_class == 0 || previous_class < current)
          first = result[starter]
          composite = table.fetch("composition")[first + char]
          if composite.nil? &&
               %w[patchwork patchwork-1.3.2 phpbb-bundled].include?(normalizer)
            composite, consumed =
              compose_jamo_sequence(first, char, ordered[index + 1], normalizer)
            consumed_index = index + 1 if consumed
          elsif composite.nil?
            composite = compose_hangul(first, char)
          end
        end
        if composite
          result[starter] = composite
        else
          starter = result.length if current == 0
          result << char
          previous_class = current
        end
      end
      result.join
    end

    def self.compose_hangul(first, second)
      leading = first.ord - 0x1100
      vowel = second.ord - 0x1161
      if (0...19).cover?(leading) && (0...21).cover?(vowel)
        return (0xAC00 + (leading * 21 + vowel) * 28).chr(Encoding::UTF_8)
      end
      syllable = first.ord - 0xAC00
      trailing = second.ord - 0x11A7
      if (0...11_172).cover?(syllable) && syllable % 28 == 0 &&
           (1...28).cover?(trailing)
        (first.ord + trailing).chr(Encoding::UTF_8)
      end
    end

    # Both bundled sources compose L + V with at most one following T.
    # Patchwork includes TBase (U+11A7); phpBB starts at U+11A8 and preserves
    # precomposed syllables instead of decomposing them before this step.
    # Neither source composes an existing LV syllable with a following T.
    def self.compose_jamo_sequence(first, second, following, normalizer)
      unless (0x1100..0x1112).cover?(first.ord) &&
               (0x1161..0x1175).cover?(second.ord)
        return nil, false
      end
      syllable = compose_hangul(first, second)
      trailing = following&.ord
      minimum = normalizer == "phpbb-bundled" ? 0x11A8 : 0x11A7
      if trailing && (minimum..0x11C2).cover?(trailing)
        [(syllable.ord + trailing - 0x11A7).chr(Encoding::UTF_8), true]
      else
        [syllable, false]
      end
    end
    private_class_method :compose_hangul, :compose_jamo_sequence
  end
end
