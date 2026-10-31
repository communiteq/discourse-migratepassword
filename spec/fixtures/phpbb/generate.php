<?php
// Run in isolated PHP against the named source; never load config.php or a DB.
$root = rtrim($argv[1], '/') . '/';
$profile = $argv[2];
if (!in_array($profile, array('3.0', 'legacy', 'legacy-bom', 'current'), true)) {
    throw new \RuntimeException('Unknown preprocessing profile');
}
define('IN_PHPBB', true);
$phpbb_root_path = $root;
$phpEx = 'php';
$old = $profile === '3.0';
if ($old) {
    define('STRIP', false);
    require $root . 'includes/functions.php';
    // Keep unique_id() from attempting to update a database-backed random seed.
    $config = array('rand_seed' => 'Synthetic-fixture-seed', 'rand_seed_last_update' => PHP_INT_MAX);
    $drivers = array('phpass_h' => null, 'md5' => null);
} else {
    if (is_file($root . 'vendor/autoload.php')) {
        require $root . 'vendor/autoload.php';
    }
    require $root . 'includes/utf/utf_tools.php';
    spl_autoload_register(function ($class) use ($root) {
        $file = $root . str_replace('\\', '/', $class) . '.php';
        if (is_file($file)) {
            require $file;
        }
    });
    $config = new \phpbb\config\config(array());
    $helper = new \phpbb\passwords\driver\helper($config);
    $drivers = array(
        'bcrypt' => new \phpbb\passwords\driver\bcrypt_2y($config, $helper),
        'bcrypt_2a' => new \phpbb\passwords\driver\bcrypt($config, $helper),
        'phpass_h' => new \phpbb\passwords\driver\salted_md5($config, $helper),
        'phpass_p' => new \phpbb\passwords\driver\phpass($config, $helper),
    );
    $default = 'bcrypt';
    if (class_exists('phpbb\\passwords\\driver\\argon2id')) {
        $drivers['argon2id'] = new \phpbb\passwords\driver\argon2id($config, $helper);
        $drivers['argon2i'] = new \phpbb\passwords\driver\argon2i($config, $helper);
        $default = 'argon2id';
    }
    $manager = new \phpbb\passwords\manager($config, $drivers, new \phpbb\passwords\helper(), array($default));
    $request_helper = new \phpbb\request\type_cast_helper();
}
$passwords = array(
    'ascii' => 'Synthetic-Tea-2026',
    'html' => 'Synthetic-Tea<&">-2026',
    'apostrophe' => "Synthetic'Tea-2026",
    'unicode' => "Synthetic-Cafe\xCC\x81-2026",
    'whitespace' => " \tSynthetic-Tea\r\n2026\0\x0B ",
    'form_feed' => "\x0CSynthetic-Tea-2026\x0C",
    'carriage_return' => "Synthetic-Tea\r2026",
    'entity' => 'Synthetic-&amp;-2026',
    'nbsp' => "\xC2\xA0Synthetic-Tea-2026\xC2\xA0",
    'bom' => "\xEF\xBB\xBFSynthetic-Tea-2026",
    'internal_bom' => "Synthetic-\xEF\xBB\xBFTea-2026",
    'bom_between_cr_lf' => "Synthetic-Tea\r\xEF\xBB\xBF\n2026",
    'leading_lf' => "\nSynthetic-Tea-2026",
    'leading_crlf' => "\r\nSynthetic-Tea-2026",
    'space_then_lf' => " \nSynthetic-Tea-2026",
    'short' => 'a&',
);
if (isset($argv[3]) && $argv[3] === 'original-regression') {
    $passwords = array('html' => $passwords['html']);
    $drivers = array('bcrypt' => $drivers['bcrypt']);
}
require __DIR__ . '/../../../script/phpbb_normalizer.php';

if (!$old) {
    $profile .= ':' . phpbb_normalizer_id($root);
}
$fixtures = array();
$preprocessing = array();
foreach ($passwords as $name => $original) {
    $prepared = '';
    if ($old) {
        // 3.0 login uses request_var(), whose set_var() trims but does not NFC-normalize.
        set_var($prepared, $original, 'string', true);
    } else {
        $request_helper->set_var($prepared, $original, 'string', true, false);
        $prepared = trim($prepared);
    }
    $preprocessing[$name] = array('original' => $original, 'prepared' => $prepared, 'profile' => $profile);
    if ((isset($argv[3]) && $argv[3] === 'preprocessing') || $prepared === '' || $prepared === '0') {
        continue;
    }
    foreach ($drivers as $algorithm => $driver) {
        // phpBB's bcrypt $2a$ driver rejects a password ending in a high-bit byte.
        if ($algorithm === 'bcrypt_2a' && (ord(substr($prepared, -1)) & 128)) {
            continue;
        }
        $hash = $old ? ($algorithm === 'md5' ? md5($prepared) : phpbb_hash($prepared)) : $manager->hash($prepared, $algorithm);
        $correct = $old ? phpbb_check_hash($prepared, $hash) : $manager->check($prepared, $hash);
        $wrong = $old ? phpbb_check_hash('incorrect-password', $hash) : $manager->check('incorrect-password', $hash);
        if (!$hash || !$correct || $wrong) {
            throw new \RuntimeException('Fixture generation failed: ' . $name . '/' . $algorithm);
        }
        $fixtures[$name . '_' . $algorithm] = array('profile' => $profile, 'original' => $original, 'prepared' => $prepared, 'hash' => $hash);
    }
}
echo json_encode(isset($argv[3]) && $argv[3] === 'preprocessing' ? $preprocessing : $fixtures, JSON_PRETTY_PRINT) . "\n";
