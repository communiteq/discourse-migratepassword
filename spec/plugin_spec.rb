# frozen_string_literal: true

require "rails_helper"

describe "discourse-migratepassword user login cleanup" do
  fab!(:user) { Fabricate(:user) }

  it "removes import_pass custom field on successful login event" do
    user.custom_fields["import_pass"] = "legacy-hash"
    user.save_custom_fields

    DiscourseEvent.trigger(:user_logged_in, user)

    expect(user.reload.custom_fields["import_pass"]).to be_nil
  end

  it "does nothing when import_pass is absent" do
    expect { DiscourseEvent.trigger(:user_logged_in, user) }.not_to raise_error
  end
end
