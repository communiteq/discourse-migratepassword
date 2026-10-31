# frozen_string_literal: true

require "rails_helper"

RSpec.describe ::AlternativePassword do
  fixtures =
    Dir[File.join(__dir__, "fixtures/phpbb/*.json")]
      .sort
      .each_with_object({}) do |path, all|
        source = File.basename(path, ".json")
        JSON
          .parse(File.read(path))
          .each { |name, fixture| all["#{source}/#{name}"] = fixture }
      end

  before do
    SiteSetting.migratepassword_enabled = true
    SiteSetting.migratepassword_allow_insecure_passwords = false
  end

  def import_fixture(user, fixture)
    user.custom_fields["import_pass"] = fixture.fetch("hash")
    user.custom_fields["import_pass_phpbb_profile"] = fixture.fetch("profile")
    user.save_custom_fields
  end

  def expect_retired(user)
    expect(user.reload.custom_fields).not_to have_key("import_pass")
    expect(user.custom_fields).not_to have_key("import_pass_phpbb_profile")
  end

  Dir[File.join(__dir__, "fixtures/phpbb/preprocessing/*.json")]
    .sort
    .each do |path|
    source = File.basename(path, ".json")
    JSON
      .parse(File.read(path))
      .each do |name, fixture|
        it "matches #{source} preprocessing for #{name}" do
          expect(
            described_class.prepare_phpbb_password(
              fixture.fetch("original"),
              profile: fixture.fetch("profile")
            )
          ).to eq(fixture.fetch("prepared"))
        end
      end
  end

  fixtures.each do |name, fixture|
    context "with the phpBB-generated #{name} fixture" do
      it "reproduces phpBB's request and database-auth preprocessing" do
        original = fixture.fetch("original").dup.freeze
        expect(
          described_class.prepare_phpbb_password(
            original,
            profile: fixture.fetch("profile")
          )
        ).to eq(fixture.fetch("prepared"))
      end

      it "verifies only the prepared candidate without mutating either argument" do
        original = fixture.fetch("original").dup.freeze
        imported = fixture.fetch("hash").dup.freeze
        expect(
          described_class.check_phpbb(
            original,
            imported,
            profile: fixture.fetch("profile")
          )
        ).to eq(true)
        expect(
          described_class.check_phpbb(
            "incorrect-password",
            imported,
            profile: fixture.fetch("profile")
          )
        ).to eq(false)
      end

      it "converts to the typed native password and retires the imported fields" do
        user = Fabricate(:user)
        import_fixture(user, fixture)
        SiteSetting.migratepassword_allow_insecure_passwords =
          true if name.include?("/short_")
        expect(user.reload.confirm_password?(fixture.fetch("original"))).to eq(
          true
        )
        expect_retired(user)
        SiteSetting.migratepassword_enabled = false
        expect(user.reload.confirm_password?(fixture.fetch("original"))).to eq(
          true
        )
        if fixture.fetch("original") != fixture.fetch("prepared")
          expect(
            user.reload.confirm_password?(fixture.fetch("prepared"))
          ).to eq(false)
        end
      end
    end
  end

  context "with a pending phpBB password" do
    fab!(:user)
    let(:fixture) { fixtures.fetch("phpbb-3.3.19/html_argon2id") }

    before { import_fixture(user, fixture) }

    it "rejects wrong passwords without losing the imported fields" do
      expect(user.reload.confirm_password?("incorrect-password")).to eq(false)
      expect(user.reload.custom_fields["import_pass"]).to eq(
        fixture.fetch("hash")
      )
      expect(user.custom_fields["import_pass_phpbb_profile"]).to eq(
        fixture.fetch("profile")
      )
    end

    it "does not accept the HTML-escaped representation as a raw fallback" do
      expect(user.reload.confirm_password?(fixture.fetch("prepared"))).to eq(
        false
      )
      expect(user.reload.custom_fields["import_pass"]).to eq(
        fixture.fetch("hash")
      )
    end

    it "honors the disabled-plugin setting" do
      SiteSetting.migratepassword_enabled = false
      expect(user.reload.confirm_password?(fixture.fetch("original"))).to eq(
        false
      )
      expect(user.reload.custom_fields["import_pass"]).to eq(
        fixture.fetch("hash")
      )
    end

    it "keeps native authentication first and cleans up both fields after login" do
      native = "Existing-Native<&>-2026"
      user.password = native
      user.save!
      [true, false].each do |enabled|
        SiteSetting.migratepassword_enabled = enabled
        expect(user.reload.confirm_password?(native)).to eq(true)
      end
      DiscourseEvent.trigger(:user_logged_in, user)
      expect_retired(user)
    end

    it "enforces the native password policy unless legacy passwords are allowed" do
      short = fixtures.fetch("phpbb-3.3.19/short_argon2id")
      import_fixture(user, short)
      SiteSetting.min_password_length = 10
      expect(user.reload.confirm_password?(short.fetch("original"))).to eq(
        false
      )
      expect(user.reload.custom_fields["import_pass"]).to eq(
        short.fetch("hash")
      )
      expect(user.custom_fields["import_pass_phpbb_profile"]).to eq(
        short.fetch("profile")
      )
      SiteSetting.migratepassword_allow_insecure_passwords = true
      expect(user.reload.confirm_password?("wrong")).to eq(false)
      expect(user.reload.confirm_password?(short.fetch("original"))).to eq(true)
      expect_retired(user)
      SiteSetting.migratepassword_enabled = false
      expect(user.reload.confirm_password?(short.fetch("original"))).to eq(true)
    end

    it "fails closed for a null, empty, or unknown profile, even if the raw hash would verify" do
      [nil, "", "unknown"].each do |profile|
        UserCustomField.where(
          user_id: user.id,
          name: "import_pass_phpbb_profile"
        ).update_all(value: profile)
        expect(user.reload.confirm_password?(fixture.fetch("prepared"))).to eq(
          false
        )
        expect(user.reload.custom_fields["import_pass"]).to eq(
          fixture.fetch("hash")
        )
      end
    end
  end

  it "does not preprocess unmarked bcrypt or phpass credentials from other systems" do
    %w[html_bcrypt html_phpass_h html_phpass_p].each do |name|
      fixture = fixtures.fetch("phpbb-3.3.19/#{name}")
      expect(
        described_class.check_all(
          fixture.fetch("original"),
          fixture.fetch("hash").dup
        )
      ).to eq(false)
      expect(
        described_class.check_all(
          fixture.fetch("prepared"),
          fixture.fetch("hash").dup
        )
      ).to eq(true)
    end
  end

  it "does not change unmarked bcrypt conversion" do
    password = "Other-System<&>-2026"
    user = Fabricate(:user)
    user.custom_fields["import_pass"] = BCrypt::Password.create(password).to_s
    user.save_custom_fields
    expect(user.reload.confirm_password?(password)).to eq(true)
    expect_retired(user)
    SiteSetting.migratepassword_enabled = false
    expect(user.reload.confirm_password?(password)).to eq(true)
  end

  it "preserves unmarked IPB salts that happen to contain a phpbb prefix" do
    password = "Other-System<&>-2026"
    salt = "phpbb:current"
    hash =
      Digest::MD5.hexdigest(
        Digest::MD5.hexdigest(salt) + Digest::MD5.hexdigest(password)
      )
    user = Fabricate(:user)
    user.custom_fields["import_pass"] = "#{salt}:#{hash}"
    user.save_custom_fields
    expect(user.reload.confirm_password?(password)).to eq(true)
    expect_retired(user)
  end

  it "rejects invalid UTF-8 and values that phpBB treats as an empty password" do
    [
      nil,
      "bad\xFF".dup.force_encoding(Encoding::UTF_8),
      "",
      " \t\r\n\0\v",
      "0"
    ].each do |password|
      expect(
        described_class.check_phpbb(
          password,
          "invalid-hash",
          profile: "current:unicode-17.0.0"
        )
      ).to eq(false)
    end
  end

  it "rejects malformed hashes and unsupported profiles" do
    [nil, "", "invalid-hash", "$argon2id$invalid"].each do |hash|
      expect(
        described_class.check_phpbb(
          "Synthetic-Tea-2026",
          hash,
          profile: "current:unicode-17.0.0"
        )
      ).to eq(false)
    end
    hash = fixtures.fetch("phpbb-3.3.19/ascii_bcrypt").fetch("hash")
    [nil, "", "unknown"].each do |profile|
      expect(
        described_class.check_phpbb(
          "Synthetic-Tea-2026",
          hash,
          profile: profile
        )
      ).to eq(false)
    end
  end

  it "selects the modern and legacy BOM behavior explicitly" do
    legacy = fixtures.fetch("phpbb-3.1.12/bom_bcrypt")
    modern = fixtures.fetch("phpbb-3.3.19/bom_bcrypt")
    expect(
      described_class.check_phpbb(
        legacy.fetch("original"),
        legacy.fetch("hash"),
        profile: "current:unicode-17.0.0"
      )
    ).to eq(false)
    expect(
      described_class.check_phpbb(
        modern.fetch("original"),
        modern.fetch("hash"),
        profile: "legacy:phpbb-bundled"
      )
    ).to eq(false)
  end

  it "keeps vBulletin's MD5-before-Argon2 fallback out of marked phpBB credentials" do
    password = "Synthetic-Argon-2026"
    hash =
      Argon2::Password.create(
        Digest::MD5.hexdigest(password),
        t_cost: 1,
        m_cost: 8
      )
    expect(described_class.check_all(password, hash.dup)).to eq(true)
    %w[
      3.0
      legacy:phpbb-bundled
      legacy-bom:unicode-17.0.0
      current:unicode-17.0.0
    ].each do |profile|
      expect(
        described_class.check_phpbb(password, hash, profile: profile)
      ).to eq(false)
    end
  end

  it "does not enable Argon2i for unmarked credentials" do
    fixture = fixtures.fetch("phpbb-3.3.19/ascii_argon2i")
    expect(
      described_class.check_all(
        fixture.fetch("original"),
        fixture.fetch("hash").dup
      )
    ).to eq(false)
  end

  it "handles ASCII input encodings without changing the original string" do
    fixture = fixtures.fetch("phpbb-3.3.19/ascii_bcrypt")
    [
      Encoding::UTF_8,
      Encoding::US_ASCII,
      Encoding::ASCII_8BIT
    ].each do |encoding|
      original = fixture.fetch("original").encode(encoding).freeze
      expect(
        described_class.prepare_phpbb_password(
          original,
          profile: "current:unicode-17.0.0"
        )
      ).to eq(fixture.fetch("prepared"))
      expect(original.encoding).to eq(encoding)
    end
  end

  it "keeps vBulletin's MD5-before-bcrypt fallback out of marked phpBB credentials" do
    password = "Synthetic-Bcrypt-2026"
    hash = BCrypt::Password.create(Digest::MD5.hexdigest(password)).to_s
    expect(described_class.check_all(password, hash.dup)).to eq(true)
    %w[
      3.0
      legacy:phpbb-bundled
      legacy-bom:unicode-17.0.0
      current:unicode-17.0.0
    ].each do |profile|
      expect(
        described_class.check_phpbb(password, hash, profile: profile)
      ).to eq(false)
    end
  end
end
