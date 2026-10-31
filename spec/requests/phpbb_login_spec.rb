# frozen_string_literal: true

require "rails_helper"

RSpec.describe "phpBB password migration", type: :request do
  %w[
    phpbb-3.0.14
    phpbb-3.1.12
    phpbb-3.2.8-regression
    phpbb-3.2.11-patchwork
    phpbb-3.2.11
    phpbb-3.3.19
  ].each do |source|
    context "with #{source}" do
      fab!(:user) { Fabricate(:user, active: true, approved: true) }
      let(:fixture) do
        fixtures =
          JSON.parse(
            File.read(File.join(__dir__, "../fixtures/phpbb/#{source}.json"))
          )
        fixtures["html_argon2id"] || fixtures["html_bcrypt"] ||
          fixtures.fetch("html_phpass_h")
      end

      before do
        SiteSetting.migratepassword_enabled = true
        SiteSetting.migratepassword_allow_insecure_passwords = false
        user.activate
        user.custom_fields["import_pass"] = fixture.fetch("hash")
        user.custom_fields["import_pass_phpbb_profile"] = fixture.fetch(
          "profile"
        )
        user.save_custom_fields
      end

      it "rejects a wrong login, converts a correct login, and then authenticates natively" do
        post "/session.json",
             params: {
               login: user.username,
               password: "incorrect-password"
             }
        expect(response.parsed_body["user"]).to be_nil
        expect(user.reload.custom_fields).to have_key("import_pass")

        post "/session.json",
             params: {
               login: user.username,
               password: fixture.fetch("original")
             }
        expect(response.status).to eq(200)
        expect(response.parsed_body["error"]).to be_nil
        expect(response.parsed_body.dig("user", "username")).to eq(
          user.username
        )
        expect(session[:current_user_id]).to eq(user.id)
        expect(user.reload.custom_fields).not_to have_key("import_pass")
        expect(user.custom_fields).not_to have_key("import_pass_phpbb_profile")

        delete "/session/#{user.username}.json"
        SiteSetting.migratepassword_enabled = false
        post "/session.json",
             params: {
               login: user.username,
               password: fixture.fetch("prepared")
             }
        expect(response.parsed_body["user"]).to be_nil
        post "/session.json",
             params: {
               login: user.username,
               password: fixture.fetch("original")
             }
        expect(response.status).to eq(200)
        expect(response.parsed_body["error"]).to be_nil
        expect(response.parsed_body.dig("user", "username")).to eq(
          user.username
        )
        expect(session[:current_user_id]).to eq(user.id)
      end
    end
  end
end
