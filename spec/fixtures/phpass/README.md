# phpass fixtures

These synthetic passwords and hashes were generated and verified with the unmodified phpBB 3.1.12 `salted_md5` (`$H$`) and `phpass` (`$P$`) drivers at `f38fce5ce570318ac64c95601e891cfe2e8f4d1a`, using PHP 5.6.40. No phpBB request preprocessing is involved.

For each driver, call `hash($password, $setting)` with the password in the JSON and settings `$H$5abcdefgh`, `$H$6abcdefgh`, and `$H$7abcdefgh` for cost exponents 7, 8, and 9, respectively (replace `$H$` with `$P$` for the other driver). The `short` fixture uses cost 7. Verify each result with the driver's `check()` for the correct password and an incorrect password.
