<?php
// Run with the source forum's PHP runtime and source tree. No config.php or DB is loaded.
// Also used by the synthetic fixture generator. Compatible with PHP 5.6+.
function phpbb_normalizer_source($root)
{
    if (extension_loaded('intl')) {
        if (!class_exists('IntlChar')) {
            throw new RuntimeException('This intl runtime cannot report its Unicode version; do not guess a normalizer.');
        }
        $version = implode('.', array_slice(IntlChar::getUnicodeVersion(), 0, 3));
        return array('id' => 'unicode-' . $version, 'source_signature' => 'Unicode ' . $version);
    }
    $reflection = new ReflectionFunction('utf8_normalize_nfc');
    $body = implode('', array_slice(file($reflection->getFileName()), $reflection->getStartLine() - 1, $reflection->getEndLine() - $reflection->getStartLine() + 1));
    if (strpos($body, 'utf_normalizer::nfc') !== false) {
        $files = array('includes/utf/utf_normalizer.php', 'includes/utf/data/utf_nfc_qc.php', 'includes/utf/data/utf_canonical_decomp.php', 'includes/utf/data/utf_canonical_comp.php', 'includes/utf/data/utf_normalizer_common.php');
        $signature = '';
        foreach ($files as $file) {
            $signature .= hash_file('sha256', $root . $file);
        }
        return array('id' => 'phpbb-bundled', 'source_signature' => hash('sha256', $signature));
    }
    if (class_exists('Patchwork\\PHP\\Shim\\Normalizer') && is_subclass_of('Normalizer', 'Patchwork\\PHP\\Shim\\Normalizer')) {
        $class = new ReflectionClass('Patchwork\\PHP\\Shim\\Normalizer');
        $directory = dirname($class->getFileName());
        $signature = hash_file('sha256', $class->getFileName());
        foreach (array('canonicalDecomposition', 'canonicalComposition', 'combiningClass') as $name) {
            $signature .= hash_file('sha256', $directory . '/unidata/' . $name . '.ser');
        }
        return array('id' => 'patchwork', 'source_signature' => hash('sha256', $signature), 'directory' => $directory);
    }
    throw new RuntimeException('Unsupported normalizer implementation; do not guess a profile.');
}

function phpbb_normalizer_id($root)
{
    $source = phpbb_normalizer_source($root);
    // Patchwork releases share code but can ship different Unicode data.
    $ids = $source['id'] === 'patchwork' ? array('patchwork', 'patchwork-1.3.2') : array($source['id']);
    foreach ($ids as $id) {
        $path = __DIR__ . '/../lib/phpbb_normalizers/' . $id . '.json';
        if (!is_file($path)) continue;
        $known = json_decode(file_get_contents($path), true);
        if ($known['source_signature'] === $source['source_signature']) return $id;
    }
    throw new RuntimeException('Unsupported source normalizer or unverified implementation/data; do not guess a profile.');
}

if (isset($_SERVER['SCRIPT_FILENAME']) && realpath($_SERVER['SCRIPT_FILENAME']) === __FILE__) {
    try {
        if (!isset($argv[1])) {
            throw new RuntimeException('Usage: php script/phpbb_normalizer.php /path/to/phpBB');
        }
        $phpbb_root_path = rtrim($argv[1], '/') . '/';
        $phpEx = 'php';
        define('IN_PHPBB', true);
        if (is_file($phpbb_root_path . 'vendor/autoload.php')) {
            require $phpbb_root_path . 'vendor/autoload.php';
        }
        require $phpbb_root_path . 'includes/utf/utf_tools.php';
        echo 'PHPBB_NORMALIZER=' . phpbb_normalizer_id($phpbb_root_path) . "\n";
    } catch (Exception $e) {
        fwrite(STDERR, $e->getMessage() . "\n");
        exit(1);
    }
}
