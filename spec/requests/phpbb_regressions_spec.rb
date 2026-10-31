# frozen_string_literal: true

require "rails_helper"
require "tempfile"
require "stringio"
require_relative "../../lib/phpbb_password_import"

RSpec.describe "phpBB source-runtime regressions", type: :request do
  fab!(:user) { Fabricate(:user, active: true, approved: true) }

  before do
    SiteSetting.migratepassword_enabled = false
    SiteSetting.migratepassword_allow_insecure_passwords = false
    user.activate
  end

  def prepare(fixture)
    user.custom_fields["import_pass"] = fixture.fetch("hash")
    user.save_custom_fields
    Tempfile.create("phpbb-regression-ids") do |file|
      file.write("#{user.id}\n")
      file.flush
      MigratePassword::PhpbbPasswordImport.new(
        version: fixture.fetch("version"),
        normalizer: fixture.fetch("normalizer"),
        ids_file: file.path,
        apply: true,
        output: StringIO.new
      ).run
    end
    expect(user.reload.custom_fields["import_pass"]).to eq(
      fixture.fetch("hash")
    )
    SiteSetting.migratepassword_enabled = true
  end

  Dir[File.join(__dir__, "../fixtures/phpbb/regressions/*.json")]
    .sort
    .each do |path|
    JSON
      .parse(File.read(path))
      .each do |name, fixture|
        context "with #{File.basename(path)} / #{name}" do
          it "accepts the source password after preparation and stores exactly the typed native password" do
            prepare(fixture)
            post "/session.json",
                 params: {
                   login: user.username,
                   password: fixture.fetch("original")
                 }
            expect(response.parsed_body["error"]).to be_nil
            expect(session[:current_user_id]).to eq(user.id)
            expect(user.reload.custom_fields).not_to have_key("import_pass")
            expect(user.custom_fields).not_to have_key(
              "import_pass_phpbb_profile"
            )
            SiteSetting.migratepassword_enabled = false
            expect(
              user.reload.confirm_password?(fixture.fetch("original"))
            ).to eq(true)
            if fixture.fetch("original") != fixture.fetch("prepared")
              expect(
                user.reload.confirm_password?(fixture.fetch("prepared"))
              ).to eq(false)
            end
          end

          it "matches phpBB's acceptance or rejection of the alternate candidate" do
            prepare(fixture)
            post "/session.json",
                 params: {
                   login: user.username,
                   password: fixture.fetch("alternate")
                 }
            if fixture.fetch("source_alternate")
              expect(response.parsed_body["error"]).to be_nil
              expect(session[:current_user_id]).to eq(user.id)
              SiteSetting.migratepassword_enabled = false
              expect(
                user.reload.confirm_password?(fixture.fetch("alternate"))
              ).to eq(true)
              expect(
                user.reload.confirm_password?(fixture.fetch("original"))
              ).to eq(false)
            else
              expect(session[:current_user_id]).to be_nil
              expect(user.reload.custom_fields["import_pass"]).to eq(
                fixture.fetch("hash")
              )
              expect(user.custom_fields).to have_key(
                "import_pass_phpbb_profile"
              )
            end
          end
        end
      end
  end
end
