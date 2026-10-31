# frozen_string_literal: true

require "rails_helper"
require_relative "../../lib/phpbb_normalizer"
require_relative "../../lib/phpbb_password_import"

RSpec.describe MigratePassword::PhpbbNormalizer do
  Dir[File.join(__dir__, "../fixtures/phpbb/regressions/*.json")]
    .sort
    .each do |path|
    JSON
      .parse(File.read(path))
      .each do |name, fixture|
        it "matches source request preprocessing for #{File.basename(path)} / #{name}" do
          profile =
            MigratePassword::PhpbbPasswordImport.profile_for(
              fixture.fetch("version")
            )
          expect(
            AlternativePassword.prepare_phpbb_password(
              fixture.fetch("original"),
              profile: "#{profile}:#{fixture.fetch("normalizer")}"
            )
          ).to eq(fixture.fetch("prepared"))
        end
      end
  end

  it "rejects unknown normalizers" do
    expect(described_class.normalize("Synthetic-Tea-2026", "unknown")).to be_nil
  end

  it "does not infer a normalizer from a request profile" do
    %w[
      legacy
      legacy-bom
      current
      current:unknown
      3.0:phpbb-bundled
    ].each do |profile|
      expect(
        AlternativePassword.prepare_phpbb_password(
          "Synthetic-Tea-2026",
          profile: profile
        )
      ).to be_nil
    end
  end
end
