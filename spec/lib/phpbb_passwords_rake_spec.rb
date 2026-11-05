# frozen_string_literal: true

require "rails_helper"
require "rake"

RSpec.describe Rake::Task do
  before do
    @previous_rake = Rake.application
    Rake.application = Rake::Application.new
    Rake::Task.define_task(:environment)
    load File.expand_path("../../lib/tasks/phpbb_passwords.rake", __dir__) # rubocop:disable Discourse/Plugins/UseRequireRelative -- Reload into the isolated Rake application.
    allow(ENV).to receive(:[]).and_call_original
    allow(ENV).to receive(:[]).with("PHPBB_VERSION").and_return("3.2.11")
    allow(ENV).to receive(:[]).with("PHPBB_NORMALIZER").and_return(
      "patchwork-1.3.2"
    )
    allow(ENV).to receive(:[]).with("IMPORT_ID_PREFIX").and_return("synthetic:")
    allow(ENV).to receive(:[]).with("USER_IDS_FILE").and_return(nil)
    allow(ENV).to receive(:fetch).and_call_original
    allow(ENV).to receive(:fetch).with("APPLY", "0").and_return("0")
    SiteSetting.migratepassword_enabled = false
  end

  after { Rake.application = @previous_rake }

  let(:task) { Rake::Task["migratepassword:prepare_phpbb"] }

  it "defaults to a preview" do
    expect { task.invoke }.to output(
      /Profile: legacy-bom:patchwork-1.3.2;.*\nPreview user IDs:.*\nNo changes written/m
    ).to_stdout
  end

  it "applies only with the explicit apply flag" do
    user = Fabricate(:user)
    user.custom_fields["import_id"] = "synthetic:42"
    user.custom_fields["import_pass"] = BCrypt::Password.create(
      "Synthetic-Tea-2026"
    ).to_s
    user.save_custom_fields
    allow(ENV).to receive(:fetch).with("APPLY", "0").and_return("1")
    expect { task.invoke }.to output(/Prepared passwords: 1/).to_stdout
    expect(user.reload.custom_fields["import_pass_phpbb_profile"]).to eq(
      "legacy-bom:patchwork-1.3.2"
    )
  end

  it "rejects an invalid apply flag" do
    allow(ENV).to receive(:fetch).with("APPLY", "0").and_return("yes")
    expect { expect { task.invoke }.to raise_error(SystemExit) }.to output(
      /APPLY must be 0 or 1/
    ).to_stderr
  end
end
