# frozen_string_literal: true

require "rails_helper"

RSpec.describe AlternativePassword do
  fixtures = JSON.parse(File.read(File.join(__dir__, "fixtures/phpass_utf8/hashes.json")))

  describe ".check_wordpress" do
    fixtures.each do |prefix, costs|
      it "verifies $#{prefix}$ bytes without mutating the caller's password" do
        %w[ascii unicode decomposed].each do |name|
          fixture = costs.fetch("8").fetch(name)
          password = fixture.fetch("password").dup
          original_bytes = password.bytes
          original_encoding = password.encoding

          expect(described_class.check_wordpress(password, fixture.fetch("hash"))).to eq(true)
          expect(password.bytes).to eq(original_bytes)
          expect(password.encoding).to eq(original_encoding)
          expect(described_class.check_wordpress(password.freeze, fixture.fetch("hash"))).to eq(true)
        end
      end
    end
  end
end
