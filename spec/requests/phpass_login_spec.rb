# frozen_string_literal: true

require "rails_helper"

RSpec.describe "phpass password migration", type: :request do
  fixtures =
    JSON.parse(File.read(File.join(__dir__, "../fixtures/phpass/hashes.json")))

  before do
    SiteSetting.migratepassword_enabled = true
    SiteSetting.migratepassword_allow_insecure_passwords = false
  end

  it "restricts the configured minimum to 7 through 30" do
    [6, 31].each do |cost|
      expect {
        SiteSetting.migratepassword_phpass_minimum_cost = cost
      }.to raise_error(Discourse::InvalidParameters)
    end
    [7, 30].each do |cost|
      SiteSetting.migratepassword_phpass_minimum_cost = cost
      expect(SiteSetting.migratepassword_phpass_minimum_cost).to eq(cost)
    end
  end

  fixtures.each do |prefix, cases|
    context "with $#{prefix}$ hashes" do
      fab!(:user) { Fabricate(:user, active: true, approved: true) }
      let(:fixture) { cases.fetch("cost7") }

      before do
        user.activate
        user.custom_fields["import_pass"] = fixture.fetch("hash")
        user.save_custom_fields
      end

      def login_with(password)
        post "/session.json",
             params: {
               login: user.username,
               password: password
             }
      end

      def expect_rejected
        expect(session[:current_user_id]).to be_nil
        expect(response.parsed_body["user"]).to be_nil
        expect(user.reload.custom_fields["import_pass"]).to eq(
          fixture.fetch("hash")
        )
      end

      it "preserves the default minimum of 8" do
        expect(SiteSetting.migratepassword_phpass_minimum_cost).to eq(8)
        login_with(fixture.fetch("password"))
        expect_rejected
        expect(
          AlternativePassword.check_wordpress(
            cases.fetch("cost8").fetch("password"),
            cases.fetch("cost8").fetch("hash")
          )
        ).to eq(true)
      end

      it "enforces a higher configured minimum" do
        SiteSetting.migratepassword_phpass_minimum_cost = 9
        %w[cost7 cost8 cost9].each do |name|
          candidate = cases.fetch(name)
          expect(
            AlternativePassword.check_wordpress(
              candidate.fetch("password"),
              candidate.fetch("hash")
            )
          ).to eq(name == "cost9")
        end
      end

      it "rejects invalid or out-of-range encoded costs even when the minimum is 7" do
        SiteSetting.migratepassword_phpass_minimum_cost = 7
        %w[4 T !].each do |encoded_cost|
          hash = fixture.fetch("hash").dup
          hash[3] = encoded_cost
          expect(
            AlternativePassword.check_wordpress(fixture.fetch("password"), hash)
          ).to eq(false)
        end
      end

      it "rejects a wrong password, converts a cost-7 login, and then authenticates natively" do
        SiteSetting.migratepassword_phpass_minimum_cost = 7
        login_with("incorrect-password")
        expect_rejected
        login_with(fixture.fetch("password"))
        expect(response.status).to eq(200)
        expect(response.parsed_body["error"]).to be_nil
        expect(session[:current_user_id]).to eq(user.id)
        expect(user.reload.custom_fields).not_to have_key("import_pass")

        reset!
        SiteSetting.migratepassword_enabled = false
        SiteSetting.migratepassword_phpass_minimum_cost = 8
        login_with("incorrect-password")
        expect(session[:current_user_id]).to be_nil
        login_with(fixture.fetch("password"))
        expect(session[:current_user_id]).to eq(user.id)
      end

      it "honors the disabled-plugin setting" do
        SiteSetting.migratepassword_phpass_minimum_cost = 7
        SiteSetting.migratepassword_enabled = false
        login_with(fixture.fetch("password"))
        expect_rejected
      end

      context "with a password below the native length requirement" do
        let(:fixture) { cases.fetch("short") }

        it "requires the existing legacy-password policy to permit conversion" do
          SiteSetting.migratepassword_phpass_minimum_cost = 7
          SiteSetting.min_password_length = 10
          login_with(fixture.fetch("password"))
          expect_rejected
          SiteSetting.migratepassword_allow_insecure_passwords = true
          login_with("incorrect-password")
          expect_rejected
          login_with(fixture.fetch("password"))
          expect(session[:current_user_id]).to eq(user.id)
          expect(user.reload.custom_fields).not_to have_key("import_pass")
          SiteSetting.migratepassword_enabled = false
          expect(
            user.reload.confirm_password?(fixture.fetch("password"))
          ).to eq(true)
        end
      end
    end
  end
end
