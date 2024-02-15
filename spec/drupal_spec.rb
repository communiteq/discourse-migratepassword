require 'rails_helper'

RSpec.describe ::AlternativePassword do
  PASSWORD = "password"
  DRUPAL6_PASSWORD_HASH = "5f4dcc3b5aa765d61d8327deb882cf99"
  DRUPAL6_TO_7_PASSWORD_HASH = "U$S$9Mgn6dLYe2Fhpoh/w/B1i53mzshiyA4BscrcKyMXNrccMeWnRK.W"
  DRUPAL7_PASSWORD_HASH = "$S$DNX2.wYzcK0HRWPjbbA2xXbHXsOizN.WxHYcn6o.KMwRyTGLtStx"

  it "passes with drupal 7 hashes" do
    expect(::AlternativePassword.check_drupal7(PASSWORD, DRUPAL7_PASSWORD_HASH)).to be true
  end

  it "passes with drupal 7 hashes imported from Drupal 6" do
    expect(::AlternativePassword.check_drupal7(PASSWORD, DRUPAL6_TO_7_PASSWORD_HASH)).to be true
  end

  it "passes with drupal 6 hashes" do
    expect(::AlternativePassword.check_md5(PASSWORD, DRUPAL6_PASSWORD_HASH)).to be true
  end
end

