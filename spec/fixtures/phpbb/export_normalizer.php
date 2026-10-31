<?php
$phpbb_root_path = rtrim($argv[1], '/') . '/';
$phpEx = 'php';
define('IN_PHPBB', true);
if (is_file($phpbb_root_path . 'vendor/autoload.php')) require $phpbb_root_path . 'vendor/autoload.php';
require $phpbb_root_path . 'includes/utf/utf_tools.php';
require __DIR__ . '/../../../script/phpbb_normalizer.php';
$source = phpbb_normalizer_source($phpbb_root_path);
$id = $source['id'];
if ($id === 'phpbb-bundled') {
    require $phpbb_root_path . 'includes/utf/data/utf_canonical_decomp.php';
    require $phpbb_root_path . 'includes/utf/data/utf_canonical_comp.php';
    require $phpbb_root_path . 'includes/utf/data/utf_normalizer_common.php';
    $d = $utf_canonical_decomp; $c = $utf_canonical_comp; $cc = $utf_combining_class;
} elseif ($id === 'patchwork') {
    $directory = $source['directory'];
    $d = unserialize(file_get_contents($directory . '/unidata/canonicalDecomposition.ser'));
    $c = unserialize(file_get_contents($directory . '/unidata/canonicalComposition.ser'));
    $cc = unserialize(file_get_contents($directory . '/unidata/combiningClass.ser'));
} else {
    $d = $c = $cc = array();
    for ($cp = 0; $cp <= 0x10ffff; ++$cp) {
        if (($cp >= 0xd800 && $cp <= 0xdfff) || ($cp >= 0xac00 && $cp <= 0xd7a3)) continue;
        $char = IntlChar::chr($cp);
        $class = IntlChar::getCombiningClass($cp);
        if ($class) $cc[$char] = $class;
        $decomposed = Normalizer::normalize($char, Normalizer::NFD);
        if ($char !== $decomposed) {
            $d[$char] = $decomposed;
            $parts = preg_split('//u', $decomposed, -1, PREG_SPLIT_NO_EMPTY);
            if (count($parts) > 1 && Normalizer::normalize($decomposed) === $char) {
                $last = array_pop($parts);
                $c[Normalizer::normalize(implode('', $parts)) . $last] = $char;
            }
        }
    }
}
ksort($d); ksort($c); ksort($cc);
$result = array('id' => phpbb_normalizer_id($phpbb_root_path), 'source_signature' => $source['source_signature'], 'decomposition' => $d, 'composition' => $c, 'combining_class' => $cc);
echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "\n";
