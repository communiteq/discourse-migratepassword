<?php
$phpbb_root_path=rtrim($argv[1],'/').'/'; $phpEx='php'; define('IN_PHPBB',true);
if(is_file($phpbb_root_path.'vendor/autoload.php')) require $phpbb_root_path.'vendor/autoload.php';
require $phpbb_root_path.'includes/utf/utf_tools.php';
$in=fopen($argv[2], 'r');
while (($line=fgets($in)) !== false) {
 $value=json_decode($line,true);
 echo json_encode(utf8_normalize_nfc($value)),"\n";
}
