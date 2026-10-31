# discourse-migratepassword

Let members sign in with passwords imported from another system. After verifying an imported password, the plugin stores it as a native Discourse password and removes the imported hash.

## Installation

For a standard, self-hosted Discourse installation, follow the [Discourse plugin installation guide](https://meta.discourse.org/t/install-plugins-on-a-self-hosted-site/19157) using this repository:

```text
https://github.com/communiteq/discourse-migratepassword.git
```

For a development checkout, run the following from the Discourse directory, then restart Discourse:

```sh
bundle exec rake plugin:install repo=https://github.com/communiteq/discourse-migratepassword
```

## Import passwords

Store each source password hash in the user's `import_pass` custom field. For example, in the Discourse Rails console:

```ruby
user = User.find_by!(username: 'user')
user.custom_fields['import_pass'] = '5f4dcc3b5aa765d61d8327deb882cf99'
user.save_custom_fields
```

The `migratepassword_enabled` site setting enables imported-password verification and defaults to `true`. Native Discourse authentication is checked first. Conversion normally uses Discourse's validations; the existing `migratepassword_allow_insecure_passwords` setting allows saving without validation and defaults to `false`.

For phpBB imports, complete [phpBB password preparation](#phpbb-password-preparation) before enabling imported-password login.

### Import from CSV

The `migratepassword:import` Rake task creates users from a CSV file and attaches imported hashes to new or existing users. Run it from the Discourse directory inside the container:

```sh
bin/rake 'migratepassword:import[public/uploads/filename.csv]'
```

The file must be accessible inside the container. On a standard installation, a file placed at `/var/discourse/shared/standalone/uploads/filename.csv` on the host is accessible as `public/uploads/filename.csv` inside the container.

| CSV column | Required | Value |
| --- | --- | --- |
| `user_email` | Yes | Email address; identifies an existing user if present. |
| `name` | Yes | Display name for a new user. |
| `user_login` | No | Username for a new user. |
| `password` | No | Plaintext password for a new user. |
| `blocked` | No | `true` suspends the user; `false` leaves suspension unchanged. |
| `import_pass` | No | Migrated password hash. |

For phpBB, disable `migratepassword_enabled` before importing, then follow the preparation steps below. The CSV task stores hashes without identifying them as phpBB credentials.

## phpBB password preparation

phpBB's standard database authentication preprocesses passwords before checking their hashes. For example, it verifies `Foo&2026` using `Foo&amp;2026`. Checking the raw input can therefore reject the correct password. Hash formats cannot identify phpBB credentials because other applications use the same formats.

**Updating this plugin alone preserves existing behavior.** Accounts without `import_pass_phpbb_profile` use the existing verifier, and converted accounts continue using native Discourse authentication. The `migratepassword:prepare_phpbb` task explicitly enables phpBB preprocessing for selected pending credentials from fresh or existing imports. No Discourse importer change is required.

### 1. Identify the source version and normalizer

Read the phpBB version from the source database's `<table_prefix>config` table, where `config_name = 'version'`. Use the source forum's version at migration time; do not infer it from the hashes. Check the [supported versions](#supported-phpbb-versions-and-runtimes) below.

For **phpBB 3.1–3.3**, run the included read-only probe with the source forum's actual PHP runtime, extensions, dependencies, and source tree:

```sh
php /path/to/discourse-migratepassword/script/phpbb_normalizer.php /path/to/phpBB
```

The probe prints `PHPBB_NORMALIZER=...` for a recognized implementation. Copy that assignment into both the preview and apply commands. It does not load `config.php` or connect to the database.

A phpBB release can use native PHP intl or a bundled fallback with different normalization behavior, so the version alone is insufficient. Running the probe in an unrelated PHP container identifies that container's behavior. If the probe rejects the source, do not substitute another normalizer. Historical changes to the source forum's authentication runtime may require further investigation.

For **phpBB 3.0**, omit `PHPBB_NORMALIZER`; that release line does not perform Unicode normalization.

### 2. Import passwords and select the phpBB accounts

For a fresh import, run the ordinary importer with password import enabled and `migratepassword_enabled` disabled. For an existing import, the task prepares only accounts that still have an imported hash.

Choose exactly one account scope:

- `IMPORT_ID_PREFIX`: a known, source-specific prefix in the users' `import_id` custom fields. Do not assume the importer supplied a prefix or use one shared by multiple sources.
- `USER_IDS_FILE`: a file containing one positive **Discourse user ID** per line, explicitly identified as belonging to this phpBB import. Use this when import IDs do not distinguish the source. The file must be accessible inside the Discourse container.

### 3. Preview, apply, and re-enable the plugin

Run the task from the Discourse directory inside the container. Replace the example version, normalizer, and account scope with the values identified above. Preview is the default and prints counts and Discourse user IDs without displaying passwords or hashes.

For a source verified to use native Unicode 17.0.0 and an actual import-ID prefix of `forum-a:`:

```sh
PHPBB_VERSION=3.3.19 PHPBB_NORMALIZER=unicode-17.0.0 IMPORT_ID_PREFIX='forum-a:' bin/rake migratepassword:prepare_phpbb
```

Or, for the same source with an explicit user-ID file:

```sh
PHPBB_VERSION=3.3.19 PHPBB_NORMALIZER=unicode-17.0.0 USER_IDS_FILE=/path/to/phpbb-user-ids.txt bin/rake migratepassword:prepare_phpbb
```

Review the selected IDs, disable `migratepassword_enabled`, and rerun the same command with `APPLY=1`. For the first example:

```sh
PHPBB_VERSION=3.3.19 PHPBB_NORMALIZER=unicode-17.0.0 IMPORT_ID_PREFIX='forum-a:' APPLY=1 bin/rake migratepassword:prepare_phpbb
```

Re-enable `migratepassword_enabled` after preparation succeeds. The task does not change that setting itself. If the import or account selection changes between preview and apply, preview again before applying.

Preparation adds only the private `import_pass_phpbb_profile` custom field and preserves `import_pass` byte for byte. It skips converted accounts and leaves already prepared accounts unchanged. Conflicting profiles, unsupported hash formats, invalid account selection, or unrecognized source configurations abort the batch without partial writes.

### Verification and conversion

The profile selects phpBB's HTML escaping with `ENT_COMPAT`, NUL removal, PHP trimming, and source-specific Unicode, BOM, and newline handling. Only the verification candidate is transformed. Successful conversion stores **the password the member actually typed** as the native Discourse password and removes both imported-password fields.

Verification of the imported hash uses only the selected phpBB profile, without raw-input or alternate-normalizer fallbacks. Native authentication, plugin disabling, and the existing legacy-password policy retain their precedence and behavior.

Custom importers can set `import_pass` to the original hash and `import_pass_phpbb_profile` to `<request profile>:<normalizer ID>` (or just `3.0`), using the values below. The profile field is private and is not sent to the browser.

### Supported phpBB versions and runtimes

The source version selects request handling; the probe result selects the normalizer. Version boundaries were inspected in phpBB source. Runtime fixtures cover the representative releases listed below, not every intervening release.

| Source versions | Request profile | Behavior |
| --- | --- | --- |
| 3.0.0–3.0.14 | `3.0` | No Unicode normalization; preserves U+FEFF; trims before UTF-8 validation. |
| 3.1.0–3.1.12, 3.2.0–3.2.9, 3.3.0 | `legacy` | Source-specific normalization; preserves U+FEFF; rejects leading LF after CR/NUL handling. |
| 3.2.10–3.2.11, 3.3.1–3.3.10 | `legacy-bom` | Source-specific normalization; removes U+FEFF; retains leading-LF rejection. |
| 3.3.11–3.3.19 | `current` | Source-specific normalization; removes U+FEFF; accepts leading LF before trimming. |

The probe recognizes these normalizers:

| `PHPBB_NORMALIZER` | Source implementation |
| --- | --- |
| `phpbb-bundled` | Verified phpBB 3.1 bundled normalizer. |
| `patchwork` | Patchwork 1.3.1. |
| `patchwork-1.3.2` | Patchwork 1.3.2. |
| `unicode-17.0.0` | Native PHP intl with Unicode 17.0.0. |

Patchwork is a PHP library that some phpBB installations use as a Unicode-normalization fallback. Its supported versions have different Unicode data and are identified separately.

Bundled implementations are fingerprinted. Unknown implementations, differing fingerprints, and other Unicode data versions are rejected. Native intl on PHP 5.6 lacks the probe's `IntlChar` version API and cannot be identified. Supporting another runtime requires independent validation of its tables and algorithm. See the [normalizer documentation](lib/phpbb_normalizers/README.md) for source identities, Hangul behavior, and provenance.

Versions outside the listed ranges are rejected. Customized request helpers, authentication providers, and compound/converter-specific hashes require separate assessment.

Supported formats include legacy MD5, phpass `$H$`/`$P$`, bcrypt `$2y$`/`$2a$`, and Argon2id/Argon2i. The phpBB `$2a$` verifier rejects a final high-bit byte even beyond bcrypt's 72-byte boundary; `$2y$` retains its source behavior.

## Tests and fixture provenance

Validation includes independently phpBB-generated synthetic credentials from 3.0.14, 3.1.12, 3.2.11, and 3.3.19, plus regressions for bundled normalizers. Tests cover preparation, source acceptance/rejection, native conversion, imported-field removal, authentication policies, and isolation from other imported systems. See the [fixture documentation](spec/fixtures/phpbb/README.md) for source/runtime details and regeneration commands.

## License

[GPL v2](LICENSE). The normalization data includes the source-specific notices described in the [normalizer documentation](lib/phpbb_normalizers/README.md).
