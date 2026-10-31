# frozen_string_literal: true

require "rails_helper"
require "stringio"
require "tempfile"
require_relative "../../lib/phpbb_password_import"

RSpec.describe MigratePassword::PhpbbPasswordImport do
  fab!(:selected, :user)
  fab!(:other, :user)
  let(:output) { StringIO.new }
  let(:fixture) do
    JSON.parse(
      File.read(File.join(__dir__, "../fixtures/phpbb/phpbb-3.3.19.json"))
    ).fetch("html_argon2id")
  end

  before do
    SiteSetting.migratepassword_enabled = false
    [selected, other].each do |user|
      user.custom_fields["import_pass"] = fixture.fetch("hash")
      user.custom_fields["unrelated"] = "keep"
      user.custom_fields["import_id"] = (
        if user == selected
          "forum-a:42"
        else
          "forum-b:42"
        end
      )
      user.save_custom_fields
    end
  end

  def prepare(**options)
    described_class.new(
      version: "3.3.19",
      normalizer: "unicode-17.0.0",
      prefix: "forum-a:",
      output: output,
      **options
    ).run
  end

  def with_ids(contents)
    Tempfile.create("phpbb-user-ids") do |file|
      file.write(contents)
      file.flush
      yield file.path
    end
  end

  {
    "3.0.0" => "3.0",
    "3.0.14" => "3.0",
    "3.1.0" => "legacy",
    "3.1.12" => "legacy",
    "3.2.0" => "legacy",
    "3.2.9" => "legacy",
    "3.2.10" => "legacy-bom",
    "3.2.11" => "legacy-bom",
    "3.3.0" => "legacy",
    "3.3.1" => "legacy-bom",
    "3.3.10" => "legacy-bom",
    "3.3.11" => "current",
    "3.3.19" => "current"
  }.each do |version, profile|
    it "selects #{profile} for phpBB #{version}" do
      expect(described_class.profile_for(version)).to eq(profile)
    end
  end

  it "rejects missing, malformed, and unverified future versions" do
    [
      nil,
      "",
      "latest",
      "3.0.15",
      "3.1.13",
      "3.2.12",
      "3.3.20",
      "3.3.19-custom",
      "4.0.0",
      "4.0.0-a3-dev",
      "3.3.019"
    ].each do |version|
      expect { described_class.profile_for(version) }.to raise_error(
        ArgumentError
      )
    end
  end

  it "previews without writing and prints no hashes" do
    expect { prepare }.not_to change { UserCustomField.count }
    expect(selected.reload.custom_fields).not_to have_key(
      described_class::PROFILE_FIELD
    )
    expect(output.string).to include(
      "Preview user IDs: #{selected.id}",
      "No changes written"
    )
    expect(output.string).not_to include(
      fixture.fetch("hash"),
      other.id.to_s + ","
    )
  end

  it "marks only the selected pending account, preserves fields, and is idempotent" do
    selected_before = selected.reload.custom_fields.dup
    other_before = other.reload.custom_fields.dup
    prepare(apply: true)
    expect(selected.reload.custom_fields).to eq(
      selected_before.merge(
        described_class::PROFILE_FIELD => "current:unicode-17.0.0"
      )
    )
    expect(other.reload.custom_fields).to eq(other_before)
    expect { prepare(apply: true) }.not_to change { UserCustomField.count }
    expect(output.string).to include("Prepared passwords: 0")
    SiteSetting.migratepassword_enabled = true
    expect(selected.reload.confirm_password?(fixture.fetch("original"))).to eq(
      true
    )
    expect(selected.reload.custom_fields).not_to have_key("import_pass")
    expect(selected.custom_fields).not_to have_key(
      described_class::PROFILE_FIELD
    )
    expect(selected.custom_fields["unrelated"]).to eq("keep")
    SiteSetting.migratepassword_enabled = false
    expect(selected.reload.confirm_password?(fixture.fetch("original"))).to eq(
      true
    )
  end

  it "does not touch already converted accounts or empty imported passwords" do
    selected.custom_fields.delete("import_pass")
    selected.save_custom_fields
    prepare(apply: true)
    expect(selected.reload.custom_fields).not_to have_key(
      described_class::PROFILE_FIELD
    )
    selected.custom_fields["import_pass"] = ""
    selected.save_custom_fields
    prepare(apply: true)
    expect(selected.reload.custom_fields).not_to have_key(
      described_class::PROFILE_FIELD
    )
  end

  it "requires exactly one explicit account scope" do
    [nil, "", " "].each do |prefix|
      expect { prepare(prefix: prefix) }.to raise_error(
        ArgumentError,
        /exactly one/
      )
    end
    expect { prepare(ids_file: "unused") }.to raise_error(
      ArgumentError,
      /exactly one/
    )
  end

  it "treats wildcard characters in prefixes literally" do
    selected.custom_fields["import_id"] = "forum%_:42"
    selected.save_custom_fields
    prepare(prefix: "forum%_:", apply: true)
    expect(selected.reload.custom_fields[described_class::PROFILE_FIELD]).to eq(
      "current:unicode-17.0.0"
    )
    expect(other.reload.custom_fields).not_to have_key(
      described_class::PROFILE_FIELD
    )
  end

  it "supports explicit Discourse IDs without relying on import_id" do
    selected.custom_fields.delete("import_id")
    selected.save_custom_fields
    with_ids("#{selected.id}\n#{selected.id}\n") do |path|
      prepare(prefix: nil, ids_file: path, apply: true)
    end
    expect(selected.reload.custom_fields[described_class::PROFILE_FIELD]).to eq(
      "current:unicode-17.0.0"
    )
    expect(other.reload.custom_fields).not_to have_key(
      described_class::PROFILE_FIELD
    )
  end

  it "rejects empty, malformed, and nonexistent IDs before any writes" do
    [
      "",
      "0\n",
      "-1\n",
      "#{selected.id},#{other.id}",
      "#{selected.id}\n9999999999\n"
    ].each do |contents|
      with_ids(contents) do |path|
        expect {
          prepare(prefix: nil, ids_file: path, apply: true)
        }.to raise_error(ArgumentError)
      end
    end
    expect(selected.reload.custom_fields).not_to have_key(
      described_class::PROFILE_FIELD
    )
  end

  it "refuses conflicting profiles without partially applying a batch" do
    other.custom_fields[described_class::PROFILE_FIELD] = "legacy"
    other.save_custom_fields
    expect { prepare(prefix: "forum-", apply: true) }.to raise_error(
      ArgumentError,
      /Conflicting/
    )
    expect(selected.reload.custom_fields).not_to have_key(
      described_class::PROFILE_FIELD
    )
    expect(other.reload.custom_fields[described_class::PROFILE_FIELD]).to eq(
      "legacy"
    )
  end

  it "refuses unsupported hashes without partially applying a batch or exposing hashes" do
    other.custom_fields["import_pass"] = "synthetic-unsupported-hash"
    other.save_custom_fields
    expect { prepare(prefix: "forum-", apply: true) }.to raise_error(
      ArgumentError,
      /Unsupported phpBB hash format for user ID #{other.id}; no changes applied/
    )
    expect(selected.reload.custom_fields).not_to have_key(
      described_class::PROFILE_FIELD
    )
    expect(output.string).not_to include(
      "synthetic-unsupported-hash",
      fixture.fetch("hash")
    )
  end

  it "requires the plugin to be disabled when applying but permits previews" do
    SiteSetting.migratepassword_enabled = true
    expect { prepare }.not_to raise_error
    expect { prepare(apply: true) }.to raise_error(
      ArgumentError,
      /Disable migratepassword_enabled/
    )
    expect(selected.reload.custom_fields).not_to have_key(
      described_class::PROFILE_FIELD
    )
  end

  it "accepts every independently generated supported hash" do
    Dir[File.join(__dir__, "../fixtures/phpbb/*.json")].each do |path|
      JSON
        .parse(File.read(path))
        .each_value do |data|
          selected.custom_fields["import_pass"] = data.fetch("hash")
          selected.save_custom_fields
          expect { prepare }.not_to raise_error
        end
    end
  end

  it "requires an identified source normalizer without changing any accounts" do
    [nil, "", "unknown", "unicode-999.0.0"].each do |normalizer|
      expect { prepare(normalizer: normalizer, apply: true) }.to raise_error(
        ArgumentError,
        /PHPBB_NORMALIZER/
      )
    end
    expect(selected.reload.custom_fields).not_to have_key(
      described_class::PROFILE_FIELD
    )
  end

  it "does not use a Unicode normalizer for phpBB 3.0" do
    expect { prepare(version: "3.0.14") }.to raise_error(
      ArgumentError,
      /does not use/
    )
    expect { prepare(version: "3.0.14", normalizer: nil) }.not_to raise_error
  end
end
