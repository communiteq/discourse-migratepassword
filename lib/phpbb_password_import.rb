# frozen_string_literal: true

require_relative "phpbb_normalizer"

module MigratePassword
  class PhpbbPasswordImport
    PROFILE_FIELD = "import_pass_phpbb_profile"

    def self.profile_for(version)
      match = /\A3\.([0-3])\.(0|[1-9]\d*)\z/.match(version.to_s)
      unless match
        raise ArgumentError, "Specify a supported PHPBB_VERSION (see README)"
      end
      minor, patch = match.captures.map(&:to_i)
      maximum = [14, 12, 11, 19][minor]
      if patch > maximum
        raise ArgumentError, "Unverified phpBB version; see README"
      end
      return "3.0" if minor == 0
      if minor == 1 || (minor == 2 && patch < 10) || (minor == 3 && patch == 0)
        return "legacy"
      end
      return "legacy-bom" if minor == 2 || patch < 11
      "current"
    end

    def initialize(
      version:,
      normalizer: nil,
      prefix: nil,
      ids_file: nil,
      apply: false,
      output: $stdout
    )
      @profile = self.class.profile_for(version)
      if @profile == "3.0"
        if normalizer.present?
          raise ArgumentError, "phpBB 3.0 does not use a Unicode normalizer"
        end
      else
        unless PhpbbNormalizer::TABLES.key?(normalizer)
          raise ArgumentError,
                "Specify PHPBB_NORMALIZER from the source-runtime probe (see README); do not infer it from the phpBB version"
        end
        @profile = "#{@profile}:#{normalizer}"
      end
      @prefix = prefix.presence
      @ids_file = ids_file.presence
      @apply = apply
      @output = output
      if @prefix.present? == @ids_file.present?
        raise ArgumentError,
              "Specify exactly one of IMPORT_ID_PREFIX or USER_IDS_FILE"
      end
    end

    def run
      if @apply && SiteSetting.migratepassword_enabled
        raise ArgumentError,
              "Disable migratepassword_enabled during preparation, then enable it afterward"
      end

      users = selected_users
      UserCustomField.transaction do
        # Lock the pending hashes while checking and writing their separate profile fields.
        pending =
          UserCustomField
            .where(user_id: users.select(:id), name: "import_pass")
            .where.not(value: [nil, ""])
            .order(:user_id)
        pending = pending.lock if @apply
        pending = pending.to_a
        profiles =
          UserCustomField
            .where(user_id: pending.map(&:user_id), name: PROFILE_FIELD)
            .pluck(:user_id, :value)
            .to_h
        pending.each do |field|
          if profiles.key?(field.user_id) && profiles[field.user_id] != @profile
            raise ArgumentError,
                  "Conflicting phpBB profile for user ID #{field.user_id}; no changes applied"
          end
          unless supported_hash?(field.value)
            raise ArgumentError,
                  "Unsupported phpBB hash format for user ID #{field.user_id}; no changes applied"
          end
        end

        changes = pending.reject { |field| profiles.key?(field.user_id) }
        @output.puts "Profile: #{@profile}; selected users: #{users.count}; pending passwords: #{pending.length}; already prepared: #{pending.length - changes.length}"
        @output.puts "#{@apply ? "Apply" : "Preview"} user IDs: #{changes.map(&:user_id).join(",")}"
        if @apply
          changes.each do |field|
            UserCustomField.create!(
              user_id: field.user_id,
              name: PROFILE_FIELD,
              value: @profile
            )
          end
          @output.puts "Prepared passwords: #{changes.length}"
        else
          @output.puts "No changes written. Review the selected user IDs; use APPLY=1 to apply."
        end
      end
    end

    private

    def selected_users
      if @prefix
        # Treat SQL wildcard characters in source prefixes literally.
        import_ids =
          UserCustomField.where(name: "import_id").where(
            "value LIKE ?",
            "#{ActiveRecord::Base.sanitize_sql_like(@prefix)}%"
          )
        User.where(id: import_ids.select(:user_id)).where("id > 0")
      else
        lines =
          File.readlines(@ids_file, chomp: true).map(&:strip).reject(&:empty?)
        if lines.empty? || lines.any? { |line| !line.match?(/\A[1-9]\d*\z/) }
          raise ArgumentError,
                "USER_IDS_FILE must contain one positive Discourse user ID per line"
        end
        ids = lines.map(&:to_i).uniq
        users = User.where(id: ids)
        unless users.count == ids.length
          raise ArgumentError, "USER_IDS_FILE contains nonexistent users"
        end
        users
      end
    end

    def supported_hash?(hash)
      hash.match?(/\A[0-9a-f]{32}\z/) ||
        hash.match?(/\A\$[HP]\$[.\/0-9A-Za-z]{31}\z/) ||
        hash.match?(/\A\$2[ayb]\$\d{2}\$[.\/0-9A-Za-z]{53}\z/) ||
        hash.match?(
          %r{\A\$argon2(?:id|i)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+\z}
        )
    end
  end
end
