# name: discourse-migratepassword
# about: enable alternative password hashes
# version: 0.71
# authors: Jens Maier and Michael@discoursehosting.com
# url: https://github.com/discoursehosting/discourse-migratepassword

# Usage:
# When migrating, store a custom field with the user containing the crypted password

# for vBulletin this should be #{password}:#{salt}      md5(md5(pass) + salt)
# for vBulletin5               #{token}                 bcrypt(md5(pass))
# for Phorum                   #{password}              md5(pass)
# for Wordpress                #{password}              phpass(8).crypt(pass)
# for SMF                      #{username}:#{password}  sha1(user+pass)
# for IPB                      #{salt}:#{hash}          md5(md5(salt)+md5(pass))
# for WBBlite                  #{salt}:#{hash}          sha1(salt+sha1(salt+sha1(pass)))
# for Joomla                   #{hash}:#{salt}          md5(pass+salt)
# for Joomla 3.2               #{password}              bcrypt(pass)
# for Question2Answer          #{salt}:#{passcheck}     sha1 (left(salt,8) + pass + right(salt,8))
# for Drupal 7                 #{password}              sha512(sha512(salt + pass) + pass) x iterations from salt.

#This will be applied at runtime, as authentication is attempted.  It does not apply at migration time.


gem 'bcrypt', '3.1.3'
gem 'unix-crypt', '1.3.0', :require_name => 'unix_crypt'

enabled_site_setting :migratepassword_enabled

require 'digest'
require 'openssl'
require "base64"

  class WordpressHash
    def initialize(stretch=8)
      @itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
      stretch = 8 unless (8..30).include?(stretch)
      @stretch = stretch
      @random_state = '%s%s' % [Time.now.to_f, $$]
    end

    def hash(pw)
      rnd = ''
      rnd = Phpass.random_bytes(6)
      crypt(pw, gensalt(rnd))
    end

    def check(pw, hash)
      hash.gsub! /^\$H\$/, '$P$'
      return false unless hash.start_with?('$P$')
      crypted = crypt(pw,hash)
      crypted == hash
    end

    private

    def gensalt(input)
      out = '$P$'
      out << @itoa64[[@stretch + 5, 30].min]
      out << encode64(input, 6)
      out
    end

    def crypt(pw, setting)
      out = '*0'
      out = '*1' if setting.start_with?(out)
      iter = @itoa64.index(setting[3])
      return out unless (8..30).include?(iter)
      count = 1 << iter
      salt = setting[4...12]
      return out if salt.length != 8
      hash = Digest::MD5.digest(salt + pw)
      while count > 0
        hash = Digest::MD5.digest(hash + pw)
        count -= 1
      end
      setting[0,12] + encode64(hash, 16)
    end

    def encode64(input, count)
      out = ''
      cur = 0
      while cur < count
        value = input[cur].ord
        cur += 1
        out << @itoa64[value & 0x3f]
        if cur < count
          value |= input[cur].ord << 8
        end
        out << @itoa64[(value >> 6) & 0x3f]
        break if cur >= count
        cur += 1

        if cur < count
          value |= input[cur].ord << 16
        end
        out << @itoa64[(value >> 12) & 0x3f]
        break if cur >= count
        cur += 1
        out << @itoa64[(value >> 18) & 0x3f]
      end
      out
    end
  end


  class DrupalSHA512Hash

    def initialize()
      @drupal_min_hash_count = 7
      @drupal_max_hash_count = 30
      @drupal_hash_length = 55
      @itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
      @hash = Digest::SHA2.new(512)
    end

    def check(password, crypted_pass)
      return false if password.nil? or crypted_pass.nil?

      crypt(password, crypted_pass[0..11]) == crypted_pass
    end

    def crypt(password, setting)
      if setting[0] != '$' or setting[2] != '$'
        # Wrong hash format
        return false
      end

      count_log2 = @itoa64.index(setting[3])

      if count_log2 < @drupal_min_hash_count or count_log2 > @drupal_max_hash_count
        return false
      end

      salt = setting[4..4 + 7]

      if salt.length != 8
        return false
      end

      iterations = 2 ** count_log2

      pass_hash = @hash.digest(salt + password)

      1.upto(iterations) do |i|
        pass_hash = @hash.digest(pass_hash.force_encoding(Encoding::UTF_8) + password)
      end

      hash_length = pass_hash.length

      output = setting + encode64(pass_hash, hash_length)

      if output.length != 98
        return false
      end

      return output[0..(@drupal_hash_length - 1)]
    end

    def encode64(input, count)
      output = ''
      i = 0
      while true
        value = (input[i]).ord

        i += 1

        output = output + @itoa64[value & 0x3f]
        if i < count
          value |= (input[i].ord) << 8
        end

        output = output + @itoa64[(value >> 6) & 0x3f]

        if i >= count
          break
        end

        i += 1

        if i < count
          value |= (input[i].ord) << 16
        end

        output = output + @itoa64[(value >> 12) & 0x3f]

        if i >= count
          break
        end

        i += 1

        output = output + @itoa64[(value >> 18) & 0x3f]

        if i >= count
          break
        end

      end
      return output
    end
  end

after_initialize do
 
    module ::AlternativePassword
        def confirm_password?(password)
            return true if super
            return false unless SiteSetting.migratepassword_enabled
            return false unless self.custom_fields.has_key?('import_pass')

            if AlternativePassword::check_all(password, self.custom_fields['import_pass'])
                self.password = password
                self.custom_fields.delete('import_pass')

                if SiteSetting.migratepassword_allow_insecure_passwords
                    return save(validate: false)
                else
                    return save
                end
            end
            false
        end
 
        def self.check_all(password, crypted_pass)
            AlternativePassword::check_vbulletin(password, crypted_pass) ||
            AlternativePassword::check_vbulletin5(password, crypted_pass) ||
            AlternativePassword::check_ipb(password, crypted_pass) ||
            AlternativePassword::check_smf(password, crypted_pass) ||
            AlternativePassword::check_md5(password, crypted_pass) ||
            AlternativePassword::check_bcrypt(password, crypted_pass) ||
            AlternativePassword::check_sha256(password, crypted_pass) ||
            AlternativePassword::check_wordpress(password, crypted_pass) ||
            AlternativePassword::check_wbblite(password, crypted_pass) ||
            AlternativePassword::check_unixcrypt(password, crypted_pass) ||
            AlternativePassword::check_joomla_md5(password, crypted_pass) ||
            AlternativePassword::check_joomla_3_2(password, crypted_pass) ||
            AlternativePassword::check_q2a(password, crypted_pass) ||
            AlternativePassword::check_drupal7(password, crypted_pass)
        end

        def self.check_bcrypt(password, crypted_pass)
            begin
              # allow salt:hash as well as hash
              BCrypt::Password.new(crypted_pass.rpartition(':').last) == password
            rescue
              false
            end
        end

        def self.check_vbulletin(password, crypted_pass)
            hash, salt = crypted_pass.split(':', 2)
            !salt.nil? && hash == Digest::MD5.hexdigest(Digest::MD5.hexdigest(password) + salt)
        end

        def self.check_vbulletin5(password, crypted_pass)
            # replace $2y$ with $2a$ see http://stackoverflow.com/a/20981781
            crypted_pass.gsub! /^\$2y\$/, '$2a$'
            begin
              BCrypt::Password.new(crypted_pass) == Digest::MD5.hexdigest(password)
            rescue
              false
            end
        end

        def self.check_md5(password, crypted_pass)
            crypted_pass == Digest::MD5.hexdigest(password)
        end

        def self.check_smf(password, crypted_pass)
            user, hash = crypted_pass.split(':', 2)
            sha1 = Digest::SHA1.new
            sha1.update user.downcase + password
            hash == sha1.hexdigest
        end

        def self.check_ipb(password, crypted_pass)
            # we can't use split since the salts may contain a colon
            salt = crypted_pass.rpartition(':').first
            hash = crypted_pass.rpartition(':').last
            !salt.nil? && hash == Digest::MD5.hexdigest(Digest::MD5.hexdigest(salt) + Digest::MD5.hexdigest(password))
        end

        def self.check_wordpress(password, crypted_pass)
            hasher = WordpressHash.new(8)
            hasher.check(password, crypted_pass.rpartition(':').last)
        end

        def self.check_sha256(password, crypted_pass)
            sha256 = Digest::SHA256.new
            sha256.update password
            crypted_pass == sha256.hexdigest
        end

        def self.check_wbblite(password, crypted_pass)
            salt, hash = crypted_pass.split(':', 2)
            sha1 = Digest::SHA1.hexdigest(salt + Digest::SHA1.hexdigest(salt + Digest::SHA1.hexdigest(password)))
            hash == sha1
        end

        def self.check_unixcrypt(password, crypted_pass)
            UnixCrypt.valid?(password, crypted_pass)
        end
     
        def self.check_joomla_md5(password, crypted_pass)
            hash, salt = crypted_pass.split(':', 2)
            !salt.nil? && hash == Digest::MD5.hexdigest(password + salt)
        end

        def self.check_q2a(password, crypted_pass)
            salt, hash = crypted_pass.split(':', 2)
            salt_prefix = salt[0..7] || ""
            salt_postfix = salt[-8..-1] || ""
            sha1 = Digest::SHA1.hexdigest(salt_prefix + password + salt_postfix)
            hash == sha1
        end

        def self.check_joomla_3_2(password, crypted_pass)
            crypted_pass.gsub! /^\$2y\$/, '$2a$'
            begin
              BCrypt::Password.new(crypted_pass) == password
            rescue
              false
            end
        end

        def self.check_drupal7(password, crypted_pass)
            begin
              DrupalSHA512Hash.new.check(password, crypted_pass)
            rescue
              false
             end
        end
    end
 
    class ::User
        prepend AlternativePassword
    end
 
end
