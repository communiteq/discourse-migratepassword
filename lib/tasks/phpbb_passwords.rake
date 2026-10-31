# frozen_string_literal: true

require_relative "../phpbb_password_import"

namespace :migratepassword do
  desc "Preview or mark explicitly selected pending phpBB passwords (see README)"
  task prepare_phpbb: :environment do
    apply = ENV.fetch("APPLY", "0")
    raise ArgumentError, "APPLY must be 0 or 1" if %w[0 1].exclude?(apply)
    MigratePassword::PhpbbPasswordImport.new(
      version: ENV["PHPBB_VERSION"],
      normalizer: ENV["PHPBB_NORMALIZER"],
      prefix: ENV["IMPORT_ID_PREFIX"],
      ids_file: ENV["USER_IDS_FILE"],
      apply: apply == "1"
    ).run
  rescue ArgumentError, SystemCallError => e
    abort e.message
  end
end
