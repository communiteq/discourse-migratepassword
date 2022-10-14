discourse-migratepassword
=========================

Support migrated password hashes


Installation
============

* Run `bundle exec rake plugin:install repo=http://github.com/discoursehosting/discourse-migratepassword` in your discourse directory
* Restart Discourse

Usage
=====

* Store your alternative password hashes in a custom field named `import_pass`
```
user = User.find_by(username: 'user')
user.custom_fields['import_pass'] = '5f4dcc3b5aa765d61d8327deb882cf99'
user.save
```

Rake task
=========

The plugin also features a rake task which imports users from a CSV file.
Usage: `migratepassword:import[filename.csv]`

You need to put `filename.csv` inside of the container or put it in for instance `/var/discourse/shared/standalone/uploads` outside of the container and then access it inside the container as `public/uploads/filename.csv`

The CSV file needs to have the required fields `user_email` and `name`, and optional fields `user_login`, `password` (plain text) and `import_pass` (migrated password hash).

License
=======

GPL v2
