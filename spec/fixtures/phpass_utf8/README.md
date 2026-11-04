# Generic phpass byte fixtures

These synthetic credentials use the raw `$H$` and `$P$` drivers from phpBB 3.1.12 at `f38fce5ce570318ac64c95601e891cfe2e8f4d1a`, executed with PHP 5.6.40. They do not use phpBB password preprocessing or a source-profile marker. Each fixture is verified by its PHP driver before output; the Ruby verifier under test does not generate the expected hashes.

`unicode` contains U+00E9, while `decomposed` contains U+0065 followed by U+0301. Both passwords must retain their distinct UTF-8 bytes. The `weak` password exercises the existing legacy-password policy. Cost 7 remains below the standalone plugin's supported minimum of 8.

To regenerate, mount the pinned phpBB checkout at `/phpbb` and this directory at `/fixtures` in a PHP 5.6.40 environment, then run:

```sh
php /fixtures/generate.php > hashes.json
```

The cost-8 ASCII and composed UTF-8 values also match the independently generated B-2 reviewer fixtures. All passwords and salts are synthetic.
