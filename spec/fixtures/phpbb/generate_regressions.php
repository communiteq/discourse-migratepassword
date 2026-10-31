<?php
// Synthetic request/helper/driver regression evidence; never loads site configuration.
$phpbb_root_path = rtrim($argv[1], '/') . '/';
$phpEx = 'php';
define('IN_PHPBB', true);
if (is_file($phpbb_root_path . 'vendor/autoload.php')) require $phpbb_root_path . 'vendor/autoload.php';
require $phpbb_root_path . 'includes/utf/utf_tools.php';
require __DIR__ . '/../../../script/phpbb_normalizer.php';
spl_autoload_register(function ($class) { global $phpbb_root_path; $path = $phpbb_root_path . str_replace('\\', '/', $class) . '.php'; if (is_file($path)) require $path; });
$config = new \phpbb\config\config(array());
$helper = new \phpbb\passwords\driver\helper($config);
$request = new \phpbb\request\type_cast_helper();
$drivers = array('2y' => new \phpbb\passwords\driver\bcrypt_2y($config, $helper), '2a' => new \phpbb\passwords\driver\bcrypt($config, $helper));
$normalizer = phpbb_normalizer_id($phpbb_root_path);
function prepared($value) { global $request; $result = ''; $request->set_var($result, $value, 'string', true, false); return trim($result); }
$pairs = array(
 'kaithi' => array(json_decode('"Synthetic-\\ud804\\udc99\\ud804\\udcba-2026"'), json_decode('"Synthetic-\\ud804\\udc9a-2026"')),
 'grantha' => array(json_decode('"Synthetic-\\ud804\\udf47\\ud804\\udf3e-2026"'), json_decode('"Synthetic-\\ud804\\udf4b-2026"')),
 'noncharacter' => array(json_decode('"Synthetic-\\ufffe-2026"'), json_decode('"Synthetic-\\ufffd-2026"')),
 'hangul' => array(json_decode('"Synthetic-\\u1100\\u1161\\u11a8-2026"'), json_decode('"Synthetic-\\uac01-2026"')),
 'ordering' => array(json_decode('"Synthetic-a\\u0301\\u0323-2026"'), json_decode('"Synthetic-a\\u0323\\u0301-2026"')),
);
if (isset($argv[3]) && $argv[3] === 'hangul') {
    // These sequences exercise the source implementation's Hangul lookahead,
    // including TBase itself and a second trailing Jamo after it is consumed.
    $pairs = array(
        'jamo_tbase' => array(json_decode('"Synthetic-\u1100\u1161\u11a7-2026"'), json_decode('"Synthetic-\uac00-2026"')),
        'syllable_tbase' => array(json_decode('"Synthetic-\uac00\u11a7-2026"'), json_decode('"Synthetic-\uac00-2026"')),
        'tbase_then_trailing' => array(json_decode('"Synthetic-\u1100\u1161\u11a7\u11a8-2026"'), json_decode('"Synthetic-\uac00\u11a8-2026"')),
        'blocked_tbase' => array(json_decode('"Synthetic-\u1100\u1161\u0301\u11a7-2026"'), json_decode('"Synthetic-\uac00\u0301\u11a7-2026"')),
    );
}
if (isset($argv[3]) && $argv[3] === 'bundled-hangul') {
    // The bundled source preserves precomposed LV + T, but composes L + V + T.
    $pairs = array(
        'precomposed_trailing' => array(json_decode('"Synthetic-\uac00\u11a8-2026"'), json_decode('"Synthetic-\uac01-2026"')),
        'decomposed_trailing' => array(json_decode('"Synthetic-\u1100\u1161\u11a8-2026"'), json_decode('"Synthetic-\uac01-2026"')),
        'last_precomposed_trailing' => array(json_decode('"Synthetic-\ud788\u11c2-2026"'), json_decode('"Synthetic-\ud7a3-2026"')),
        'tbase_then_trailing' => array(json_decode('"Synthetic-\u1100\u1161\u11a7\u11a8-2026"'), json_decode('"Synthetic-\uac00\u11a7\u11a8-2026"')),
        'blocked_trailing' => array(json_decode('"Synthetic-\u1100\u1161\u0301\u11a8-2026"'), json_decode('"Synthetic-\uac00\u0301\u11a8-2026"')),
    );
}
if (isset($argv[3]) && $argv[3] === 'patchwork-data') {
    // Patchwork 1.3.2 assigns combining classes absent from the 1.3.1 data.
    $pairs = array(
        'nko_ordering' => array(json_decode('"Synthetic-a\u0305\u07fd-2026"'), json_decode('"Synthetic-a\u07fd\u0305-2026"')),
        'malayalam_ordering' => array(json_decode('"Synthetic-a\u0305\u0d3b-2026"'), json_decode('"Synthetic-a\u0d3b\u0305-2026"')),
    );
}
$result = array();
foreach ($pairs as $name => $pair) {
    foreach (array($pair, array_reverse($pair)) as $index => $values) {
        $driver = $drivers['2y']; $original = $values[0]; $alternate = $values[1];
        $hash = $driver->hash(prepared($original));
        if (!$hash || !$driver->check(prepared($original), $hash) || $driver->check('incorrect-password', $hash)) throw new RuntimeException('Source verification failed');
        $result[$name . '_' . $index] = array('version' => $argv[2], 'normalizer' => $normalizer, 'original' => $original, 'prepared' => prepared($original), 'hash' => $hash, 'alternate' => $alternate, 'source_alternate' => $driver->check(prepared($alternate), $hash));
    }
}
foreach ((isset($argv[3]) && in_array($argv[3], array('hangul', 'bundled-hangul', 'patchwork-data'), true) ? array() : $drivers) as $name => $driver) {
    $original = 'Synthetic-Tea-' . str_repeat('&', 14);
    $alternate = $original . json_decode('"\\u00e9"');
    $hash = $driver->hash(prepared($original));
    if (!$hash || !$driver->check(prepared($original), $hash)) throw new RuntimeException('Source bcrypt verification failed');
    $result['bcrypt_suffix_' . $name] = array('version' => $argv[2], 'normalizer' => $normalizer, 'original' => $original, 'prepared' => prepared($original), 'hash' => $hash, 'alternate' => $alternate, 'source_alternate' => $driver->check(prepared($alternate), $hash));
}
echo json_encode($result, JSON_PRETTY_PRINT) . "\n";
