<?php
// Run with PHP 5.6.40 and phpBB 3.1.12 at /phpbb:
// f38fce5ce570318ac64c95601e891cfe2e8f4d1a.
// Only the raw phpass drivers are used; no phpBB password preprocessing occurs.
$root = '/phpbb/phpBB/';
foreach (array('config/config', 'passwords/driver/driver_interface', 'passwords/driver/base', 'passwords/driver/helper', 'passwords/driver/salted_md5', 'passwords/driver/phpass') as $file) require $root . 'phpbb/' . $file . '.php';
$config = new \phpbb\config\config(array());
$helper = new \phpbb\passwords\driver\helper($config);
$out = array();
foreach (array('H' => new \phpbb\passwords\driver\salted_md5($config, $helper), 'P' => new \phpbb\passwords\driver\phpass($config, $helper)) as $prefix => $driver) {
    foreach (array(7, 8) as $cost) {
        foreach (array('ascii' => 'Independent-Review-2026!', 'unicode' => "Independent-caf\xc3\xa9-2026!", 'decomposed' => "Independent-cafe\xcc\x81-2026!", 'weak' => "\xc3\xa9b7") as $name => $password) {
            $hash = $driver->hash($password, '$'.$prefix.'$'.$helper->itoa64[$cost].'review12');
            if (!$driver->check($password, $hash) || $driver->check('incorrect-password', $hash)) throw new Exception('reference failure');
            $out[$prefix][$cost][$name] = array('password' => $password, 'hash' => $hash);
        }
        if ($out[$prefix][$cost]['unicode']['hash'] === $out[$prefix][$cost]['decomposed']['hash']) throw new Exception('distinct bytes must have distinct hashes');
    }
}
echo json_encode($out, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), "\n";
