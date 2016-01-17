# name: discourse-migratepassword
# about: enable alternative password hashes
# version: 0.5
# authors: Jens Maier and Michael@discoursehosting.com
 
# uses phpass-ruby https://github.com/uu59/phpass-ruby

# Usage:
# When migrating, store a custom field with the user containing the crypted password

# for vBulletin this should be #{salt}:#{password}      md5(md5(pass) + salt)
# for Phorum                   #{password}              md5(pass)
# for Wordpress                #{password}              phpass(8).crypt(pass)
# for SMF                      #{username}:#{password}  sha1(user+pass)
# for WBBlite                  #{salt}:#{hash}          sha1(salt+sha1(salt+sha1(pass)))

gem 'bcrypt', '3.1.3'

require 'digest'

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
      crypt(pw, hash) == hash
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


after_initialize do
 
    module ::AlternativePassword
        def confirm_password?(password)
            return true if super
            return false unless self.custom_fields.has_key?('import_pass')

            if AlternativePassword::check_all(password, self.custom_fields['import_pass'])
                self.password = password
                self.custom_fields.delete('import_pass')
                return save
            end
            false
        end
 
        def self.check_all(password, crypted_pass)
            AlternativePassword::check_vbulletin(password, crypted_pass) ||
            AlternativePassword::check_ipb(password, crypted_pass) ||
            AlternativePassword::check_smf(password, crypted_pass) ||
            AlternativePassword::check_md5(password, crypted_pass) ||
            AlternativePassword::check_wordpress(password, crypted_pass) ||
            AlternativePassword::check_bcrypt(password, crypted_pass) ||
            AlternativePassword::check_sha256(password, crypted_pass) ||
            AlternativePassword::check_wbblite(password, crypted_pass) 
        end

        def self.check_bcrypt(password, crypted_pass)
            begin
              BCrypt::Password.new(crypted_pass) == password
            rescue
              false
            end
        end

        def self.check_vbulletin(password, crypted_pass)
            hash, salt = crypted_pass.split(':', 2)
            !salt.nil? && hash == Digest::MD5.hexdigest(Digest::MD5.hexdigest(password) + salt)
        end

        def self.check_md5(password, crypted_pass)
            crypted_pass == Digest::MD5.hexdigest(password)
        end

        def self.check_smf(password, crypted_pass)
            user, hash = crypted_pass.split(':', 2)
            sha1 = Digest::SHA1.new
            sha1.update user + password
            hash == sha1.hexdigest
        end

        def self.check_ipb(password, crypted_pass)
            salt, hash = crypted_pass.split(':', 2)
            !salt.nil? && hash == Digest::MD5.hexdigest(Digest::MD5.hexdigest(salt) + Digest::MD5.hexdigest(password))
        end

        def self.check_wordpress(password, crypted_pass)
            hasher = WordpressHash.new(8)
            hasher.check(password, crypted_pass)
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
    end
 
    class ::User
        prepend AlternativePassword
    end
 
end

