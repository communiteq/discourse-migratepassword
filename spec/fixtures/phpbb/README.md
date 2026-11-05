# phpBB-generated synthetic password fixtures

All credentials are synthetic. Expected preprocessing and acceptance come from the named PHP source's actual request helper and password implementation, not Ruby. Generators do not load `config.php` or connect to a database. Each positive hash is checked against correct and wrong candidates in PHP.

## Latest-release matrix

| Source | Revision | Runtime and normalizer | Main hash fixtures |
| --- | --- | --- | --- |
| 3.0.14 | 11242dd07d6359a725f22f3674028adfdddb49d6 | PHP 5.6.40; no normalizer | 32: phpass $H$ and legacy MD5 |
| 3.1.12 | f38fce5ce570318ac64c95601e891cfe2e8f4d1a | PHP 5.6.40; `phpbb-bundled` | 55: bcrypt $2y$/$2a$ and phpass $H$/$P$ |
| 3.2.11 | 22c3b7edd6ebbad3007aecc4466a496d2701ecb1 | PHP 8.5.12; `unicode-17.0.0` | 55: bcrypt $2y$/$2a$ and phpass $H$/$P$ |
| 3.2.11 | Same revision | PHP 7.2.34 without intl; `patchwork-1.3.2` | 55: bcrypt $2y$/$2a$ and phpass $H$/$P$ |
| 3.3.19 | 10356c2c3be3804402c7616e18bb53d54c02f143 | PHP 8.5.12; `unicode-17.0.0` | 95: Argon2id/Argon2i, bcrypt $2y$/$2a$, and phpass $H$/$P$ |

These five runtime configurations contain 292 positive hashes and 80 preprocessing-only cases. Latest releases for 3.0, 3.1, 3.2, and 3.3 were resolved on 2026-10-30. Native intl used ICU 78.1. Composer dependencies were installed inside isolated containers; phpBB 3.2.11 locks Patchwork 1.3.2. This is representative release/runtime coverage, not every environment that those releases can use.

The 16 inputs exercise ASCII, ENT_COMPAT escaping, apostrophes, Unicode composition, CR/LF, NUL, PHP trim boundaries, form feeds, existing entities, nonbreaking spaces, U+FEFF, leading newlines, and short passwords. phpBB 3.1.12 covers U+FEFF preservation; 3.2.11 covers removal. Source inspection places BOM removal at 3.2.10/3.3.1 and the newer leading-newline behavior at 3.3.11. Not every intervening release was executed.

## Regenerate the matrix

Run inside a compatible PHP container with the source root containing `includes/` and, for later releases, `phpbb/`. Use the request profile from the main README:

```sh
php -d display_errors=stderr generate.php /path/to/phpBB-3.3.19 current > phpbb-3.3.19.json
php -d display_errors=stderr generate.php /path/to/phpBB-3.3.19 current preprocessing > preprocessing/phpbb-3.3.19.json
php -d display_errors=stderr generate.php /path/to/phpBB-3.2.11 legacy-bom > phpbb-3.2.11-patchwork.json
```

The generator uses `set_var(..., 'string', true)` and `phpbb_hash()`/`phpbb_check_hash()` for 3.0. Later sources use `type_cast_helper::set_var(..., 'string', true, false)`, PHP `trim()`, and the phpBB password manager. Positive fixtures exclude source-rejected prepared passwords and the final-high-bit case rejected by bcrypt $2a$. Random salts change regenerated hashes; preprocessing and acceptance must match. Direct dependency deprecation notices to stderr so they do not corrupt the JSON.

## Original login regression

`phpbb-3.2.8-regression.json` retains one HTML/bcrypt fixture from the original failure's source, identifying as 3.2.8 with Patchwork 1.3.1 on PHP 7.2.34. It is not a second full release matrix. Reproduce with `php generate.php /path/to/phpBB legacy original-regression`. The ordinary model and HTTP tests check this original regression alongside the latest-release configurations.

## Unicode and bcrypt regressions

`php generate_regressions.php /path/to/phpBB VERSION` produces source hashes and alternate-acceptance results for Kaithi, Grantha, noncharacters, Hangul, combining order, and HTML-expanded bcrypt candidates with a final high-bit byte. The general regression files cover phpBB 3.1.12 with both its bundled normalizer and ICU 78.1, phpBB 3.2.11 with Patchwork 1.3.2, and phpBB 3.3.19 with ICU 78.1.

Focused library fixtures preserve the differences that release numbers alone cannot identify:

- `patchwork-1.3.1-data.json` and `patchwork-1.3.2-data.json`: use mode `patchwork-data`. The NKo and Malayalam sequences expose combining classes added in 1.3.2; each source records whether it accepts the alternate order.
- `patchwork-1.3.1-hangul.json` and `patchwork-1.3.2-hangul.json`: use mode `hangul`. Both versions exercise L/V plus U+11A7, precomposed LV plus U+11A7, a following trailing Jamo, and an intervening combining mark, in both directions.
- `phpbb-3.1.12-bundled-hangul.json`: use mode `bundled-hangul`. The bundled implementation distinguishes precomposed syllables from original Jamo sequences.

For example, `php generate_regressions.php /path/to/phpBB 3.2.11 patchwork-data` under the matrix's Patchwork 1.3.2 runtime regenerates that data-version fixture. The retained Patchwork 1.3.1 library fixtures use the original source and pass `3.2.8`; their JSON records that provenance explicitly. The profile ID `patchwork` selects 1.3.1, while `patchwork-1.3.2` selects 1.3.2.

Shared request tests apply preparation, exercise HTTP login with original and alternate candidates, check exact typed native-password storage, and verify imported-field retirement. The two Patchwork versions are checked separately; verification does not try both.

## Normalizer data and differential checks

`export_normalizer.php /path/to/phpBB` regenerates the selected recognized table in `lib/phpbb_normalizers/`. That directory documents implementation fingerprints, source revisions, and licenses. The source probe selects one supported implementation/data fingerprint and rejects unknown variants.

For broad comparisons, run `ruby normalizer_inputs.rb /artifacts`, then run `php -d display_errors=stderr normalizer_expected.php /path/to/phpBB /artifacts/normalization-input.jsonl > /artifacts/normalization-NORMALIZER_ID.jsonl` in the corresponding source runtime. Finally run `ruby check_normalizer.rb /artifacts NORMALIZER_ID`. The deterministic corpus covers Unicode scalars, table sequences, combining pairs, explicit algorithmic Hangul sequences, and mixed strings. Both Patchwork versions have been compared directly with PHP on 2,958,109 inputs each; finite comparisons do not prove arbitrary-string equivalence.

The complete collection contains 375 positive source-generated hashes: 292 matrix fixtures, one original regression, and 82 Unicode/bcrypt/library regressions. Runtime support is limited to the identified catalog. Testing an unchanged Ruby path establishes isolation, not compatibility with another source runtime.
