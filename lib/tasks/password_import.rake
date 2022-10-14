require 'csv'

namespace :migratepassword do
  desc "Import passwords from a CSV file"
  task :import, [:csv_file] => [:environment] do |_, args|
    abort "Please specify the CSV file to import" if args[:csv_file].blank?

    CSV.foreach(args[:csv_file], headers: true) do |new_user|
      user = User.find_by_email(new_user['user_email'])
      if user
        puts "User with email address #{new_user['user_email']} already exists"
      else
        user = User.new({
          email: new_user['user_email'],
          username: new_user['user_login'] || UserNameSuggester.suggest(new_user['email']),
          name: new_user['name'],
          password: new_user['password'] || SecureRandom.hex,
          approved: true,
          approved_by_id: -1
        })
        user.import_mode = true
        if user.save
          puts "Created user #{user.name}: username #{user.username}, email #{user.email}"
          user.activate
        else
          puts "Error creating user #{user.name}: username #{user.username}, email #{user.email}"
        end
      end
      if user.id && new_user['import_pass']
        puts "Setting password for #{user.username}"
        user.custom_fields['import_pass'] = new_user['import_pass'] 
        user.save_custom_fields(true)
      end
    end
  end
end
