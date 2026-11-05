# frozen_string_literal: true

require "rails_helper"

RSpec.describe SessionController, type: :request do
  fixtures = JSON.parse(File.read(File.join(__dir__, "../fixtures/phpass_utf8/hashes.json")))

  fab!(:user) { Fabricate(:user, active: true, approved: true) }
  let!(:native_password_hash) { user.user_password.reload.password_hash }

  before do
    user.activate
    SiteSetting.migratepassword_enabled = true
    SiteSetting.migratepassword_allow_insecure_passwords = false
  end

  def import_fixture(fixture)
    user.custom_fields["import_pass"] = fixture.fetch("hash")
    user.save_custom_fields
  end

  def login_with(password)
    post "/session.json", params: { login: user.username, password: password }
  end

  def expect_rejected(fixture)
    expect(response.status).to eq(200)
    expect(response.parsed_body["error"]).to eq(I18n.t("login.incorrect_username_email_or_password"))
    expect(response.parsed_body["user"]).to be_nil
    expect(session[:current_user_id]).to be_nil
    expect(user.reload.custom_fields["import_pass"]).to eq(fixture.fetch("hash"))
    expect(user.user_password.reload.password_hash).to eq(native_password_hash)
  end

  def expect_authenticated
    expect(response.status).to eq(200)
    expect(response.parsed_body["error"]).to be_nil
    expect(response.parsed_body.dig("user", "id")).to eq(user.id)
    expect(session[:current_user_id]).to eq(user.id)
    expect(user.reload.custom_fields).not_to have_key("import_pass")
  end

  describe "#create" do
    fixtures.each do |prefix, costs|
      %w[ascii unicode decomposed].each do |name|
        it "converts $#{prefix}$ #{name} bytes and authenticates the original password natively" do
          fixture = costs.fetch("8").fetch(name)
          different_password =
            if name == "unicode"
              costs.fetch("8").fetch("decomposed").fetch("password")
            elsif name == "decomposed"
              costs.fetch("8").fetch("unicode").fetch("password")
            else
              "incorrect-password"
            end
          import_fixture(fixture)

          login_with(different_password)
          expect_rejected(fixture)
          login_with(fixture.fetch("password"))
          expect_authenticated

          reset!
          SiteSetting.migratepassword_enabled = false
          login_with(different_password)
          expect(response.status).to eq(200)
          expect(response.parsed_body["error"]).to eq(I18n.t("login.incorrect_username_email_or_password"))
          expect(session[:current_user_id]).to be_nil
          login_with(fixture.fetch("password"))
          expect_authenticated
        end
      end

      it "retains $#{prefix}$ UTF-8 credentials when the plugin is disabled" do
        fixture = costs.fetch("8").fetch("unicode")
        import_fixture(fixture)
        SiteSetting.migratepassword_enabled = false

        login_with(fixture.fetch("password"))

        expect_rejected(fixture)
      end

      it "requires the existing legacy-password policy for a short $#{prefix}$ UTF-8 password" do
        fixture = costs.fetch("8").fetch("weak")
        import_fixture(fixture)
        SiteSetting.min_password_length = 10

        login_with(fixture.fetch("password"))
        expect_rejected(fixture)
        SiteSetting.migratepassword_allow_insecure_passwords = true
        login_with("incorrect-password")
        expect_rejected(fixture)
        login_with(fixture.fetch("password"))
        expect_authenticated

        reset!
        SiteSetting.migratepassword_enabled = false
        login_with(fixture.fetch("password"))
        expect_authenticated
      end

      it "preserves rejection of cost-7 $#{prefix}$ UTF-8 credentials by default" do
        fixture = costs.fetch("7").fetch("unicode")
        import_fixture(fixture)

        login_with(fixture.fetch("password"))

        expect_rejected(fixture)
      end
    end
  end
end
