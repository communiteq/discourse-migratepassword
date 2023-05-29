# frozen_string_literal: true

require "mysql2"
require "digest"

require File.expand_path(File.dirname(__FILE__) + "/base.rb")

# Before running this script, paste these lines into your shell,
# then use arrow keys to edit the values
=begin
export FLUXBB_HOST="localhost"
export FLUXBB_DB="fluxbb"
export FLUXBB_USER="root"
export FLUXBB_PW=""
export FLUXBB_PREFIX=""
=end

# Call it like this:
#   RAILS_ENV=production bundle exec ruby script/import_scripts/fluxbb.rb
class ImportScripts::FluxBB < ImportScripts::Base
  FLUXBB_HOST ||= ENV["FLUXBB_HOST"] || "localhost"
  FLUXBB_DB ||= ENV["FLUXBB_DB"] || "fluxbb"
  BATCH_SIZE ||= 1000
  FLUXBB_USER ||= ENV["FLUXBB_USER"] || "root"
  FLUXBB_PW ||= ENV["FLUXBB_PW"] || ""
  FLUXBB_PREFIX ||= ENV["FLUXBB_PREFIX"] || ""

  def initialize
    super

    @client =
      Mysql2::Client.new(
        host: FLUXBB_HOST,
        username: FLUXBB_USER,
        password: FLUXBB_PW,
        database: FLUXBB_DB,
      )
  end

  def execute
    import_users
  end

  def import_users
    puts "", "creating users"

    total_count = mysql_query("SELECT count(*) count FROM #{FLUXBB_PREFIX}users;").first["count"]

    batches(BATCH_SIZE) do |offset|
      results =
        mysql_query(
          "SELECT id, username, password, realname name, url website, email email, registered created_at,
                registration_ip registration_ip_address, last_visit last_visit_time,
                last_email_sent last_emailed_at, location, group_id
         FROM #{FLUXBB_PREFIX}users
         LIMIT #{BATCH_SIZE}
         OFFSET #{offset};",
        )


      update_users(results, total: total_count, offset: offset) do |user|
        {
          username: user["username"],
          password: user["password"]
        }
      end
    end
  end

  def update_users(results, opts = {})
      created = 0
      skipped = 0
      failed = 0
      total = opts[:total] || results.count

      results.each do |result|
        u = yield(result)
        # block returns nil to skip a user
        if u.nil?
          skipped += 1
        else
          user = User.find_by(username: u[:username])

          if user.present?
            puts "Password: " + u[:password]
            user.custom_fields['import_pass'] = u[:password]
            user.save_custom_fields(true)
            user.save
            created += 1
          else
            puts "User not found"
          end
            end

          print_status(
            created + skipped + failed + (opts[:offset] || 0),
            total,
            get_start_time("users"),
            )
      end

      [created, skipped]
    end

  def mysql_query(sql)
    @client.query(sql, cache_rows: false)
  end
end

ImportScripts::FluxBB.new.perform
