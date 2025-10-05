<?php
/**
################################################################################
# Contact Form Ingress - secure, schema-less intake endpoint (JSON or form)
# This script is property of eXtremeSHOK.com.
# You are free to use, modify and distribute, however you may not remove this notice.
# Copyright (c) Adrian Jon Kriel :: admin@extremeshok.com
################################################################################
# Script updates, documentation and issue tracker: https://github.com/extremeshok/contact-form-ingress
################################################################################
# License: MIT (https://opensource.org/license/mit/)
################################################################################
# Assumptions: PHP 8.1+ with cURL/SQLite, HTTPS deployment and writable storage dir outside web root.
# Configuration: Review and customise the $CFG array below before putting into production.
################################################################################
*/

declare(strict_types=1);
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Robots-Tag: noindex, nofollow, noarchive');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');

header('Pragma: no-cache');

$GLOBALS['INGRESS_CONFIG_ISSUES'] = ['fatal' => [], 'warnings' => []];
$GLOBALS['INGRESS_CLIENT_INFO'] = [
  'ip' => $_SERVER['REMOTE_ADDR'] ?? '',
  'source' => 'remote_addr',
  'chain' => []
];

function ingress_bootstrap_fail(array $issues, int $code = 500): void {
  if (!headers_sent()) {
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
  }
  echo json_encode([
    'ok' => false,
    'error' => 'config_error',
    'issues' => array_values($issues),
  ]);
  exit;
}

function ingress_collect_config_issues(array $cfg): array {
  $fatal = [];
  $warnings = [];

  $secret = (string)($cfg['secret'] ?? '');
  if ($secret === '' || $secret === 'CHANGE_ME_LONG_RANDOM') {
    $fatal[] = 'secret must be replaced with a long random string';
  }

  if (isset($cfg['json_forward_secret'])) {
    $jfSecret = (string)$cfg['json_forward_secret'];
    if ($jfSecret === '' || $jfSecret === 'CHANGE_ME_json_forward_secret') {
      $fatal[] = 'json_forward_secret must be configured with a non-empty secret';
    }
  }

  $notifyRaw = strtolower((string)($cfg['notify_targets'] ?? ''));
  $emailEnabled = strpos($notifyRaw, 'email') !== false;
  if ($emailEnabled) {
    $smtp = (array)($cfg['smtp'] ?? []);
    $host = trim((string)($smtp['host'] ?? ''));
    $user = trim((string)($smtp['user'] ?? ''));
    $pass = (string)($smtp['pass'] ?? '');
    $auth = strtolower((string)($smtp['auth'] ?? 'auto'));
    if ($host === '' || $host === 'smtp.example.com') {
      $fatal[] = 'smtp.host must be configured with your mail server';
    }
    $needsCredentials = !in_array($auth, ['none', ''], true);
    if ($needsCredentials) {
      if ($user === '' || $user === 'you@example.com') {
        $fatal[] = 'smtp.user must be configured with your account user';
      }
      if ($pass === '' || $pass === 'APP_PASSWORD') {
        $fatal[] = 'smtp.pass must be configured with your account password';
      }
    }
  }

  return ['fatal' => array_values(array_unique($fatal)), 'warnings' => array_values(array_unique($warnings))];
}

function ingress_current_cmd(): string {
  static $cmd = null;
  if ($cmd !== null) {
    return $cmd;
  }
  $cmd = isset($_GET['cmd']) ? (string)$_GET['cmd'] : '';
  if ($cmd === '' && !empty($_SERVER['QUERY_STRING'])) {
    parse_str($_SERVER['QUERY_STRING'], $qsTmp);
    if (isset($qsTmp['cmd'])) {
      $cmd = (string)$qsTmp['cmd'];
    }
  }
  return $cmd;
}

function ingress_is_diagnostics_request(string $cmd): bool {
  return in_array($cmd, ['health', 'check'], true);
}

// Robust error handling/logging
error_reporting(E_ALL);
set_error_handler(function($errno, $errstr, $errfile, $errline){
  // Convert warnings/notices to exceptions we can log uniformly
  if (error_reporting() === 0) return false; // silenced with @
  throw new ErrorException($errstr, 0, $errno, $errfile, $errline);
});
register_shutdown_function(function(){
  $e = error_get_last();
  if ($e && in_array($e['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR], true)) {
    log_event('fatal', ['type'=>$e['type'], 'message'=>$e['message'], 'file'=>$e['file'], 'line'=>$e['line']]);
    if (!headers_sent()) http_response_code(500);
    echo json_encode(['ok'=>false,'error'=>'Server error']);
  }
});

// ===================== CONFIG =====================
$CFG = [
  'version'          => '1.0.1',
  // Security
  'secret'           => 'CHANGE_ME_LONG_RANDOM', // set this to a long random string
  'allowed_origins'  => [
    'https://example.com',
    'http://localhost',
  ],
  'site_keys'        => [], // e.g. ['krishka-main-2025'] to restrict accepted site_key values
  'max_bytes'        => 100 * 1024, // 100 KiB
  'min_dwell_ms'     => 1500,
  'token_min_age'    => 10,            // seconds
  'token_max_age'    => 7200,         // 2 hours
  'rate_limit'       => ['window_sec' => 300, 'max_per_ip' => 5],

  // Storage outside web root (defaults to parent directory of this script)
  'storage_dir'      => (is_writable(dirname(__DIR__)) ? dirname(__DIR__) : __DIR__),
  'db_name_file'     => '.db_name',

  // Email notify
  'email' => [
    'to'   => ['you@example.com'],      // set your recipients here
    'subject_prefix' => 'Contact :: New enquiry — ',
  ],
  'dedupe_window_sec' => 3600,  // suppress duplicates (same email+message) within 1 hour
  'smtp_retries'      => 2,     // number of additional retries on transient errors
  'smtp_retry_sleep_ms' => 500, // base backoff between retries

  // Validation knobs / anti-abuse
  'min_name_chars'     => 6,
  'min_email_chars'    => 8,
  'min_phone_chars'    => 10,
  'min_message_chars'  => 40,
  'allow_links_in_message' => false, // block links by default
  'max_fields'         => 30,        // hard cap on total fields
  'require_ts_echo'    => false,     // extra anti-bot: echo token ts in hidden field

  // SMTP (required; native socket, no mail() fallback). secure: 'tls' | 'ssl' | 'none'
  'smtp' => [
    'host'   => 'smtp.example.com',
    'user'   => 'you@example.com',
    'pass'   => 'APP_PASSWORD',
    'port'   => 587,
    'secure' => 'tls',
    'auth'   => 'login',   // auto|login|plain|none
    'helo'   => 'example.com',        // EHLO/HELO name
    'verify_peer'       => true,
    'verify_peer_name'  => true,
    'allow_self_signed' => false,
  ],

  'smtp_fallback' => true, // rotate to ssl:465 or none:25 on transient/TLS errors

  // Feature gating for diagnostic commands (independent of debug logging)
  'extra_cmds' => [
    'enabled'     => false,         // flip to true when you actually need the endpoints
    'health'      => false,         // enable ?cmd=health (temporary)
    'probe_smtp'  => false,         // enable ?cmd=probe_smtp (temporary)
    'version'     => false,         // enable ?cmd=version (temporary)
    'check'       => false,         // enable ?cmd=check (config self-test)
    'key'         => '',            // optional: add a long random key to gate access
    'allow_ips'   => [],            // optional: restrict to trusted IPs
    'flush_queue' => false,
  ],

  'proxy' => [
    'enabled' => false,
    'trusted_proxies' => [],        // e.g. ['10.0.0.0/8','203.0.113.10']
    'trusted_headers' => ['x-forwarded-for','x-real-ip','forwarded'],
    'max_chain' => 5,
  ],

  // Optional: forward as JSON to n8n (no page changes)
  'json_forward_url'      => '',
  'json_forward_secret'   => 'CHANGE_ME_json_forward_secret',

  // Accept payload type: 'json' | 'form' | 'both'
  'accept_payload'   => 'both',

  // Notification targets: csv of 'email', 'n8n' (default 'email')
  'notify_targets'   => 'email',

  // Async notify (reply first, then notify) — only if fastcgi_finish_request exists
  'async_notify'     => '1',

  // Timeouts (seconds)
  'smtp_timeout'     => 8,
  'forward_timeout'  => 5,
  'forward_connect'  => 3,
  'forward_retries'        => 2,
  'forward_retry_sleep_ms' => 400,
  'forward_queue_enabled'  => false, // queue feature disabled by default
  'forward_queue_on_fail'  => false, // only queue when enabled & true
  'queue_max_batch'        => 50,    // max rows to flush per run
  'queue_flush_on_get'     => false, // do not auto-flush on GET by default
  'retention_days'         => 90,    // purge submissions older than N days (CLI helper)
  'forward_retention_days' => 14,    // purge forwards older than N days (CLI helper)
  'log_rotate_max_kib'     => 256,   // rotate .intake.log to last N KiB (CLI helper)
  // Built-in CAPTCHA (math puzzle; no third-party). Disabled by default.
  'builtin_captcha' => [
    'enabled' => false,
    'min' => 1,
    'max' => 9,
    'ops' => ['+'], // supported: '+' and '-'
  ],
  // CAPTCHA (optional; disabled by default). provider: 'turnstile' | 'hcaptcha' | 'recaptcha_v3'
  'captcha' => [
    'enabled'  => false,
    'provider' => 'turnstile',
    'site_key' => '',
    'secret'   => '',
    'min_score'=> 0.5, // for reCAPTCHA v3
    'action'   => 'contact', // for reCAPTCHA v3: expected action
    'hostname' => '', // for reCAPTCHA v3: expected hostname (optional)
  ],
  'captcha_timeout' => 5,
  'auto_reply' => [
    'enabled' => false,
    'subject' => 'Thanks — we received your message',
    'from'    => '', // optional override; defaults to SMTP user
  ],
  // Optional email domain policy
  'email_domain_allow' => [],
  'email_domain_block' => [],
  // Optional keyword denylist (simple substring match, case-insensitive)
  'keyword_denylist' => [],           // e.g. ['viagra','casino']
  'keyword_denylist_fields' => ['message','notes','enquiry','inquiry','description','request','offer'],

  // Debug logging
  'debug'            => false,
  'debug_log'        => ((is_writable(dirname(__DIR__)) ? dirname(__DIR__) : __DIR__) . DIRECTORY_SEPARATOR . '.intake.log'),
  'debug_payload'    => false,
];

// --- Optional external config overrides (single source of truth)
// Load a PHP array from CONFIG_PATH or config.ingress.php and deep-merge into $CFG
if (!function_exists('cfg_deep_merge')) {
  function cfg_deep_merge(array $base, array $over): array {
    foreach ($over as $k=>$v) {
      if (is_array($v) && isset($base[$k]) && is_array($base[$k])) {
        $base[$k] = cfg_deep_merge($base[$k], $v);
      } else {
        $base[$k] = $v;
      }
    }
    return $base;
  }
}
try {
  $cfgPathEnv = getenv('CONFIG_PATH') ?: '';
  $cfgLocalNew = __DIR__ . DIRECTORY_SEPARATOR . 'config.ingress.php';
  $cfgPath    = '';
  if ($cfgPathEnv && is_file($cfgPathEnv)) { $cfgPath = $cfgPathEnv; }
  elseif (is_file($cfgLocalNew)) { $cfgPath = $cfgLocalNew; }
  if ($cfgPath !== '') {
    $ov = include $cfgPath;
    if (is_array($ov)) { $CFG = cfg_deep_merge($CFG, $ov); }
  }
} catch (Throwable $e) { /* ignore */ }

$GLOBALS['INGRESS_CONFIG_ISSUES'] = ingress_collect_config_issues($CFG);

// ===================== HELPERS =====================
function b64u(string $s): string { return rtrim(strtr(base64_encode($s), '+/', '-_'), '='); }
function b64u_dec(string $s){
  $s = strtr($s, '-_', '+/');
  $pad = strlen($s) % 4; if ($pad) $s .= str_repeat('=', 4 - $pad);
  return base64_decode($s);
}
function hmac(string $data, string $key): string { return hash_hmac('sha256', $data, $key, true); }
function heq(string $a, string $b): bool { return hash_equals($a, $b); }
function sanitize_header(string $s): string {
  return trim(preg_replace('/[\r\n]+/', ' ', $s)); // avoid header injection
}
function parse_targets(string $csv): array {
  $t = array_filter(array_map(function($x){ return strtolower(trim($x)); }, explode(',', $csv)));
  return [
    'email' => in_array('email', $t, true),
    'n8n'   => in_array('n8n', $t, true),
  ];
}

function ingress_ip_is_valid(string $ip): bool {
  return filter_var($ip, FILTER_VALIDATE_IP) !== false;
}

function ingress_ip_in_cidr(string $ip, string $cidr): bool {
  $cidr = trim($cidr);
  if ($cidr === '') return false;
  if (!ingress_ip_is_valid($ip)) return false;

  if (strpos($cidr, '/') === false) {
    return ingress_ip_is_valid($cidr) && strcasecmp($ip, $cidr) === 0;
  }

  [$subnet, $maskStr] = explode('/', $cidr, 2);
  if (!ingress_ip_is_valid($subnet)) return false;
  $mask = (int)$maskStr;
  $ipBin = inet_pton($ip);
  $subnetBin = inet_pton($subnet);
  if ($ipBin === false || $subnetBin === false) return false;
  $length = strlen($ipBin);
  $maxBits = $length * 8;
  if ($mask < 0 || $mask > $maxBits) return false;
  $fullBytes = intdiv($mask, 8);
  $remainingBits = $mask % 8;
  if ($fullBytes > 0 && substr($ipBin, 0, $fullBytes) !== substr($subnetBin, 0, $fullBytes)) {
    return false;
  }
  if ($remainingBits === 0) {
    return true;
  }
  $maskByte = chr((~((1 << (8 - $remainingBits)) - 1)) & 0xFF);
  return ((ord($ipBin[$fullBytes]) & ord($maskByte)) === (ord($subnetBin[$fullBytes]) & ord($maskByte)));
}

function ingress_ip_matches(string $ip, array $cidrs): bool {
  foreach ($cidrs as $cidr) {
    if (ingress_ip_in_cidr($ip, (string)$cidr)) {
      return true;
    }
  }
  return false;
}

function ingress_extract_ips_from_header(string $header, string $value): array {
  $header = strtolower($header);
  $value = trim($value);
  if ($value === '') return [];
  $ips = [];
  if ($header === 'forwarded') {
    // RFC 7239 Forwarded: for=192.0.2.60;proto=https;by=203.0.113.43
    foreach (explode(',', $value) as $part) {
      if (preg_match('/for=\"?\[?([a-fA-F0-9:\.]+)\]?\"?/i', $part, $m)) {
        $ips[] = $m[1];
      }
    }
  } else {
    foreach (explode(',', $value) as $candidate) {
      $ips[] = trim($candidate);
    }
  }
  $clean = [];
  foreach ($ips as $ip) {
    $ip = trim($ip, " \"'[]");
    if ($ip !== '' && ingress_ip_is_valid($ip)) {
      $clean[] = $ip;
    }
  }
  return $clean;
}

function ingress_resolve_client_ip(array $cfg): array {
  $remote = $_SERVER['REMOTE_ADDR'] ?? '';
  $out = [
    'ip' => $remote,
    'remote_addr' => $remote,
    'source' => 'remote_addr',
    'chain' => $remote && ingress_ip_is_valid($remote) ? [$remote] : [],
  ];

  $proxy = (array)($cfg['proxy'] ?? []);
  if (empty($proxy['enabled'])) {
    return $out;
  }

  $trusted = array_filter(array_map('trim', (array)($proxy['trusted_proxies'] ?? [])));
  if ($remote === '' || empty($trusted) || !ingress_ip_matches($remote, $trusted)) {
    return $out;
  }

  $headers = array_map('strtolower', (array)($proxy['trusted_headers'] ?? []));
  $maxChain = (int)($proxy['max_chain'] ?? 5);
  if ($maxChain <= 0) { $maxChain = 5; }

  foreach ($headers as $header) {
    $serverKey = 'HTTP_' . strtoupper(str_replace('-', '_', $header));
    if (empty($_SERVER[$serverKey])) {
      continue;
    }
    $candidates = ingress_extract_ips_from_header($header, (string)$_SERVER[$serverKey]);
    if (empty($candidates)) {
      continue;
    }
    if (count($candidates) > $maxChain) {
      $candidates = array_slice($candidates, 0, $maxChain);
    }
    $client = null;
    foreach ($candidates as $ip) {
      if (!ingress_ip_matches($ip, $trusted)) {
        $client = $ip;
        break;
      }
    }
    if ($client === null) {
      $client = $candidates[0];
    }
    $out['ip'] = $client;
    $out['source'] = $header;
    $out['chain'] = $candidates;
    $_SERVER['INGRESS_CLIENT_IP'] = $client;
    return $out;
  }

  return $out;
}

function lc_str(string $s): string {
  return function_exists('mb_strtolower') ? mb_strtolower($s, 'UTF-8') : strtolower($s);
}
function ci_contains(string $haystack, string $needle): bool {
  if ($needle === '') return false;
  if (function_exists('mb_stripos')) {
    return (mb_stripos($haystack, $needle, 0, 'UTF-8') !== false);
  }
  return (stripos($haystack, $needle) !== false);
}

function builtin_captcha_mint(array $cfg, string $secret): array {
  $min = max(0, (int)($cfg['min'] ?? 1));
  $max = max($min, (int)($cfg['max'] ?? 9));
  $ops = (array)($cfg['ops'] ?? ['+']);
  $op  = in_array('-', $ops, true) && random_int(0,1) === 1 ? '-' : '+';
  $a = random_int($min, $max);
  $b = random_int($min, $max);
  if ($op === '-' && $b > $a) { $tmp=$a; $a=$b; $b=$tmp; }
  $nonce = bin2hex(random_bytes(4));
  $payload = $a . ':' . $op . ':' . $b . ':' . $nonce;
  $sig = b64u(hmac($payload, $secret));
  $token = b64u($payload . '.' . $sig);
  $q = $a . ' ' . $op . ' ' . $b;
  return ['q'=>$q, 'token'=>$token];
}

function builtin_captcha_check(string $token, string $answer, string $secret): bool {
  $raw = b64u_dec($token);
  if (!$raw || strpos($raw, '.') === false) return false;
  [$payload, $sigIn] = explode('.', $raw, 2);
  if (!heq(b64u(hmac($payload, $secret)), $sigIn)) return false;
  $parts = explode(':', $payload);
  if (count($parts) < 4) return false;
  [$a, $op, $b] = [$parts[0], $parts[1], $parts[2]];
  $a = (int)$a; $b = (int)$b; $exp = ($op === '-') ? ($a - $b) : ($a + $b);
  return ((string)$exp === trim((string)$answer));
}

function verify_captcha(array $cfg, string $token, string $ip): array {
  // Returns ['ok'=>bool,'provider'=>string,'score'=>?float,'error'=>?string]
  $provider = strtolower((string)($cfg['provider'] ?? 'turnstile'));
  $secret   = (string)($cfg['secret'] ?? '');
  $timeout  = (int)($GLOBALS['CFG']['captcha_timeout'] ?? 5);
  if ($secret === '' || $token === '') return ['ok'=>false,'provider'=>$provider,'error'=>'missing_secret_or_token'];
  if (!function_exists('curl_init')) return ['ok'=>false,'provider'=>$provider,'error'=>'curl_missing'];
  $url = '';
  $post = ['secret'=>$secret,'response'=>$token,'remoteip'=>$ip];
  if ($provider === 'turnstile') {
    $url = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
  } elseif ($provider === 'hcaptcha') {
    $url = 'https://hcaptcha.com/siteverify';
  } else { // recaptcha_v3
    $provider = 'recaptcha_v3';
    $url = 'https://www.google.com/recaptcha/api/siteverify';
  }

  $ch = curl_init($url);
  curl_setopt_array($ch, [
    CURLOPT_POST => true,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_POSTFIELDS => http_build_query($post, '', '&'),
    CURLOPT_TIMEOUT => $timeout,
    CURLOPT_CONNECTTIMEOUT => $timeout,
    CURLOPT_HTTPHEADER => ['Content-Type: application/x-www-form-urlencoded'],
  ]);
  $resp = curl_exec($ch);
  $err  = curl_error($ch);
  curl_close($ch);
  if ($resp === false) return ['ok'=>false,'provider'=>$provider,'error'=>('curl: '.$err)];
  $j = json_decode($resp, true);
  if (!is_array($j)) return ['ok'=>false,'provider'=>$provider,'error'=>'bad_json'];
  $ok = !empty($j['success']);
  $score = isset($j['score']) ? (float)$j['score'] : null;
  if ($provider === 'recaptcha_v3') {
    $min = (float)($cfg['min_score'] ?? 0.5);
    if (!$ok || ($score !== null && $score < $min)) {
      return ['ok'=>false,'provider'=>$provider,'score'=>$score,'error'=>'low_score'];
    }
    $expectedAction = trim((string)($cfg['action'] ?? ''));
    $action = isset($j['action']) ? (string)$j['action'] : '';
    if ($expectedAction !== '' && $action !== '' && $action !== $expectedAction) {
      return ['ok'=>false,'provider'=>$provider,'score'=>$score,'error'=>'bad_action'];
    }
    $expectedHost = trim((string)($cfg['hostname'] ?? ''));
    $respHost = isset($j['hostname']) ? strtolower((string)$j['hostname']) : '';
    if ($expectedHost !== '' && $respHost !== '' && strtolower($expectedHost) !== $respHost) {
      return ['ok'=>false,'provider'=>$provider,'score'=>$score,'error'=>'bad_hostname'];
    }
  }
  return ['ok'=>$ok ? true : false, 'provider'=>$provider, 'score'=>$score, 'error'=>$ok ? null : 'not_verified'];
}

function log_event(string $stage, array $ctx = []): void {
  global $CFG, $ref, $INGRESS_CLIENT_INFO;
  if (empty($CFG['debug'])) return;
  // scrub secrets recursively
  $scrub = function($v) use (&$scrub) {
    if (is_array($v)) {
      $out = [];
      foreach ($v as $k=>$vv) {
        $kl = strtolower((string)$k);
        if ($kl === 'pass' || $kl === 'password' || $kl === 'secret' || $kl === 'json_forward_secret') {
          $out[$k] = '[redacted]';
        } else {
          $out[$k] = $scrub($vv);
        }
      }
      return $out;
    }
    return $v;
  };
  $path = (string)($CFG['debug_log'] ?? '');
  if ($path === '') {
    $base = rtrim((string)($CFG['storage_dir'] ?? __DIR__), DIRECTORY_SEPARATOR);
    $path = $base . DIRECTORY_SEPARATOR . '.intake.log';
  }
  $dir = dirname($path);
  if (!is_dir($dir)) { @mkdir($dir, 0700, true); }
  if (!is_writable($dir)) {
    $base = __DIR__;
    $bn = basename($path);
    if ($bn === '' || $bn[0] !== '.') { $bn = '.intake.log'; }
    $path = $base . DIRECTORY_SEPARATOR . $bn;
    $dir = $base;
    if (!is_dir($dir)) { @mkdir($dir, 0700, true); }
  }
  // Avoid logging secrets
  $ctx = $scrub($ctx);
  $rec = [
    'ts'    => date('c'),
    'ref'   => $ref ?? null,
    'stage' => $stage,
    'ip'    => $_SERVER['REMOTE_ADDR'] ?? '',
    'client_ip' => $INGRESS_CLIENT_INFO['ip'] ?? ($_SERVER['INGRESS_CLIENT_IP'] ?? ($_SERVER['REMOTE_ADDR'] ?? '')),
    'client_source' => $INGRESS_CLIENT_INFO['source'] ?? 'remote_addr',
    'client_chain' => $INGRESS_CLIENT_INFO['chain'] ?? [],
    'ua'    => $_SERVER['HTTP_USER_AGENT'] ?? '',
    'ctx'   => $ctx,
  ];
  $line = json_encode($rec, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
  if ($line !== false) {
    @file_put_contents($path, $line.PHP_EOL, FILE_APPEND|LOCK_EX);
  } else {
    @file_put_contents($path, '{"ts":"'.date('c').'","stage":"'.$stage.'","note":"json_encode failed"}'.PHP_EOL, FILE_APPEND|LOCK_EX);
  }
}
function json_fail(int $code, string $msg){
  global $CFG, $ref;
  if (!headers_sent()) http_response_code($code);
  global $CFG;
  if ($code === 429) {
    $w = (int)($CFG['rate_limit']['window_sec'] ?? 0);
    if ($w > 0 && !headers_sent()) header('Retry-After: ' . (string)$w);
  }
  log_event('fail', ['code'=>$code,'msg'=>$msg,'last_error'=>error_get_last()]);
  echo json_encode(['ok'=>false,'error'=>$msg]);
  exit;
}
function respond_now(array $data): void {
  if (!headers_sent()) {
    header('Content-Type: application/json; charset=utf-8');
  }
  echo json_encode($data);
  if (function_exists('fastcgi_finish_request')) {
    fastcgi_finish_request();
  } else {
    if (ob_get_level() > 0) { @ob_end_flush(); }
    @flush();
  }
}

function normalize_text(string $s): string {
  // remove zero-width and control chars except \n, unify whitespace/newlines
  $s = preg_replace("/\x{200B}|\x{200C}|\x{200D}|\x{FEFF}/u", '', $s); // zero-width
  $s = str_replace(["\r\n", "\r"], "\n", $s);
  $s = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $s);     // control chars
  $s = preg_replace('/\s+/', ' ', $s);
  return trim($s);
}
function normalize_email_for_key(string $e): string { return strtolower(trim($e)); }
function is_transient_smtp_error(?string $err): bool {
  if (!$err) return false;
  $e = strtolower($err);
  if (strpos($e,'auth') !== false || strpos($e,' 535') !== false) return false; // auth failures are permanent
  if (strpos($e,'timeout') !== false) return true;
  if (strpos($e,'connect') !== false) return true;
  if (preg_match('/unexpected\s+4\d\d/', $e)) return true; // 4xx SMTP codes
  if (strpos($e,'starttls failed') !== false) return true;
  return false;
}

function origin_from_url(string $url): string {
  $p = @parse_url($url);
  if (!$p || empty($p['scheme']) || empty($p['host'])) return '';
  $port = isset($p['port']) ? (':' . $p['port']) : '';
  return strtolower($p['scheme'] . '://' . $p['host'] . $port);
}
function is_referrer_allowed(string $ref, array $allowed): bool {
  $refOrigin = origin_from_url($ref);
  if ($refOrigin === '') return false;
  if (in_array($refOrigin, $allowed, true)) return true;
  // allow any localhost port if 'http://localhost' is allowed
  if (strpos($refOrigin, 'http://localhost:') === 0 && in_array('http://localhost', $allowed, true)) return true;
  return false;
}

function extra_cmds_check(string $cmd): void {
  global $CFG;
  $f = $CFG['extra_cmds'] ?? [];
  $ip = $_SERVER['REMOTE_ADDR'] ?? '';
  $enabled = (!empty($f['enabled']) && !empty($f[$cmd]));
  if (!$enabled) json_fail(403, 'Not allowed');
  if (!empty($f['allow_ips']) && !in_array($ip, (array)$f['allow_ips'], true)) json_fail(403, 'Not allowed');
  if (!empty($f['key'])) {
    $k = (string)($_GET['key'] ?? '');
    if (!hash_equals((string)$f['key'], $k)) json_fail(403, 'Not allowed');
  }
}

// Startup sanity warnings (logged once per request)
if ($CFG['secret'] === 'CHANGE_ME_LONG_RANDOM') {
  log_event('sanity_warn', ['note'=>'secret uses default value']);
}
if (!empty($CFG['json_forward_url']) && $CFG['json_forward_secret'] === 'CHANGE_ME_json_forward_secret') {
  log_event('sanity_warn', ['note'=>'json_forward_secret uses default value']);
}

// --- Low-level SMTP client (native sockets)
// ===================== SMTP HELPERS =====================
function smtp_send(array $smtp, array $emailCfg, array $to, string $from, ?string $replyTo, string $subject, string $body, string $ref, string $ip): array {
  // Returns ['ok'=>bool, 'error'=>?string]
  $host = (string)($smtp['host'] ?? ''); if ($host === '') return ['ok'=>false,'error'=>'SMTP host not set'];
  $port = (int)($smtp['port'] ?? 587); if ($port <= 0) $port = 587;
  $secure = strtolower((string)($smtp['secure'] ?? 'tls'));
  $timeout = (int)($smtp['timeout'] ?? 8);
  $auth = strtolower((string)($smtp['auth'] ?? 'login'));
  $user = (string)($smtp['user'] ?? '');
  $pass = (string)($smtp['pass'] ?? '');
  $helo = trim((string)($smtp['helo'] ?? ''));
  if ($helo === '') { $helo = gethostname() ?: 'localhost'; }

  log_event('smtp_connecting', ['host'=>$host,'port'=>$port,'secure'=>$secure,'auth'=>$auth,'helo'=>$helo]);

  // Provide SSL context options for both implicit SSL and STARTTLS (with SNI)
  $opts = [ 'ssl' => [
    'verify_peer'       => (bool)($smtp['verify_peer'] ?? true),
    'verify_peer_name'  => (bool)($smtp['verify_peer_name'] ?? true),
    'allow_self_signed' => (bool)($smtp['allow_self_signed'] ?? false),
    'SNI_enabled'       => true,
    'peer_name'         => $host,
  ] ];
  $ctx = stream_context_create($opts);
  $remote = ($secure === 'ssl' ? 'ssl://' : '') . $host . ':' . $port;
  $errno = 0; $errstr = '';
  $fp = @stream_socket_client($remote, $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, $ctx);
  if (!$fp) return ['ok'=>false,'error'=>"connect: $errstr ($errno)"];
  stream_set_timeout($fp, $timeout);
  $meta = stream_get_meta_data($fp);
  if (!empty($meta['timed_out'])) { @fclose($fp); return ['ok'=>false,'error'=>'connect timeout']; }

  // Read banner 220
  [$code,$resp] = smtp_expect($fp, [220], 'banner');

  // EHLO
  smtp_cmd($fp, "EHLO $helo\r\n");
  [$code,$resp] = smtp_expect($fp, [250], 'ehlo');
  $ehloResp = $resp;

  // STARTTLS if requested (explicit TLS)
  if ($secure === 'tls') {
    smtp_cmd($fp, "STARTTLS\r\n");
    [$code,$resp] = smtp_expect($fp, [220], 'starttls');
    $cryptoMethod = defined('STREAM_CRYPTO_METHOD_TLS_CLIENT') ? STREAM_CRYPTO_METHOD_TLS_CLIENT : (STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT|STREAM_CRYPTO_METHOD_TLSv1_1_CLIENT|STREAM_CRYPTO_METHOD_TLSv1_0_CLIENT);
    if (!@stream_socket_enable_crypto($fp, true, $cryptoMethod)) {
      @fclose($fp); return ['ok'=>false,'error'=>'starttls failed'];
    }
    // Re-EHLO after TLS
    smtp_cmd($fp, "EHLO $helo\r\n");
    [$code,$resp] = smtp_expect($fp, [250], 'ehlo-tls');
    $ehloResp = $resp;
  }

  // Parse EHLO capabilities to detect supported AUTH methods
  $authCaps = [];
  if (isset($ehloResp)) {
    if (preg_match('/^250[\-\s]+AUTH\s+(.+)$/mi', $ehloResp, $m)) {
      $authCaps = array_map('strtoupper', preg_split('/\s+/', trim($m[1])));
    }
  }
  log_event('smtp_ehlo_caps', ['caps'=>$authCaps]);

  // Choose auth method
  $authPref = $auth; // from config: login|plain|none|auto
  if ($authPref === 'auto') {
    if (in_array('LOGIN', $authCaps, true)) $authPref = 'login';
    elseif (in_array('PLAIN', $authCaps, true)) $authPref = 'plain';
    else $authPref = 'none';
  }
  log_event('smtp_auth_method', ['chosen'=>$authPref]);

  // AUTH with auto-select and fallback
  if ($authPref !== 'none' && $user !== '') {
    $didAuth = false; $lastErr = null;
    $tryOrder = ($authPref === 'plain') ? ['plain','login'] : (($authPref === 'login') ? ['login','plain'] : ['login','plain']);
    foreach ($tryOrder as $method) {
      if ($didAuth) break;
      try {
        if ($method === 'plain' && in_array('PLAIN', $authCaps, true)) {
          $attempts = [
            ['', $user, $pass, 'plain'],
            [$from ?: '', $user, $pass, 'plain-authzid-from'],
          ];
          $okp = false; $lastErrLocal = null;
          foreach ($attempts as [$az,$uc,$pw,$variant]) {
            try {
              $token = base64_encode("{$az}\0{$uc}\0{$pw}");
              smtp_cmd($fp, "AUTH PLAIN $token\r\n");
              [$code,$resp] = smtp_expect($fp, [235], 'auth-plain');
              $okp = true; $didAuth = true; log_event('smtp_auth_ok', ['method'=>'plain','variant'=>$variant]);
              break;
            } catch (Throwable $ee) {
              $lastErrLocal = $ee->getMessage();
              log_event('smtp_auth_retry', ['method'=>'plain','variant'=>$variant,'error'=>$lastErrLocal]);
            }
          }
          if (!$okp) { throw new Exception($lastErrLocal ?: 'auth-plain failed'); }
        } elseif ($method === 'login' && in_array('LOGIN', $authCaps, true)) {
          smtp_cmd($fp, "AUTH LOGIN\r\n");
          [$code,$resp] = smtp_expect($fp, [334], 'auth-login-username');
          smtp_cmd($fp, base64_encode($user) . "\r\n");
          [$code,$resp] = smtp_expect($fp, [334], 'auth-login-password');
          smtp_cmd($fp, base64_encode($pass) . "\r\n");
          [$code,$resp] = smtp_expect($fp, [235], 'auth-login-done');
          $didAuth = true; log_event('smtp_auth_ok', ['method'=>'login']);
        }
      } catch (Throwable $e) {
        $lastErr = $e->getMessage();
        log_event('smtp_auth_retry', ['method'=>$method, 'error'=>$lastErr]);
        // continue loop to try the other method
      }
    }
    if (!$didAuth) { @fclose($fp); return ['ok'=>false,'error'=>($lastErr ?: 'auth failed')]; }
  }

  // MAIL FROM
  $envFrom = '<' . smtp_addr($from) . '>';
  smtp_cmd($fp, "MAIL FROM:$envFrom\r\n");
  [$code,$resp] = smtp_expect($fp, [250], 'mail-from');

  // RCPT TO
  $rcptOk = 0; $rcptList = [];
  foreach ($to as $addr) {
    $addr = smtp_addr((string)$addr);
    if ($addr === '') continue;
    $rcptList[] = $addr;
    smtp_cmd($fp, "RCPT TO:<$addr>\r\n");
    [$code,$resp] = smtp_expect($fp, [250,251], 'rcpt-to');
    $rcptOk++;
  }
  if ($rcptOk === 0) { @fclose($fp); return ['ok'=>false,'error'=>'no valid recipients']; }

  // DATA
  smtp_cmd($fp, "DATA\r\n");
  [$code,$resp] = smtp_expect($fp, [354], 'data');

  // Build headers
  $domain = 'localhost'; if (strpos($from, '@') !== false) { $domain = substr(strrchr($from,'@'),1) ?: 'localhost'; }
  $headers = [];
  $headers[] = 'From: '. $from;
  $headers[] = 'To: ' . implode(', ', array_map(function($a){ return $a; }, $rcptList));
  if ($replyTo) $headers[] = 'Reply-To: ' . sanitize_header($replyTo);
  $headers[] = 'Subject: ' . sanitize_header($subject);
  $headers[] = 'Date: ' . date(DATE_RFC2822);
  $headers[] = 'Message-ID: <' . bin2hex(random_bytes(6)) . '@' . $domain . '>';
  $headers[] = 'MIME-Version: 1.0';
  $headers[] = 'Content-Type: text/plain; charset=UTF-8';
  $headers[] = 'Content-Transfer-Encoding: 8bit';
  $headers[] = 'X-Submission-Ref: ' . $ref;
  $headers[] = 'X-Client-IP: ' . $ip;
  $headers[] = 'Auto-Submitted: auto-generated';
  $headers[] = 'X-Auto-Response-Suppress: All';

  // Normalise line endings and dot-stuff (cover first line and subsequent lines)
  $msg = implode("\r\n", $headers) . "\r\n\r\n" . preg_replace("~\r?\n~", "\r\n", $body);
  $msg = preg_replace('/(^|\r\n)\./', '$1..', $msg);

  fwrite($fp, $msg . "\r\n.\r\n");
  [$code,$resp] = smtp_expect($fp, [250], 'data-dot');

  // QUIT
  smtp_cmd($fp, "QUIT\r\n");
  @fclose($fp);
  return ['ok'=>true,'error'=>null];
}
function smtp_expect($fp, array $codes, string $stage): array {
  $resp = '';
  while (true) {
    $line = fgets($fp, 4096);
    if ($line === false) { throw new Exception("$stage: connection closed"); }
    $resp .= $line;
    if (strlen($line) >= 4 && $line[3] === ' ') break; // last line
    if (strlen($line) < 4) break;
  }
  $code = (int)substr($resp, 0, 3);
  if (!in_array($code, $codes, true)) { throw new Exception("$stage: unexpected $code; resp=$resp"); }
  return [$code,$resp];
}
function smtp_cmd($fp, string $cmd): void { fwrite($fp, $cmd); }
function smtp_addr(string $addr): string {
  $addr = trim($addr);
  // Strip display names if present
  if (preg_match('/<([^>]+)>/', $addr, $m)) { $addr = $m[1]; }
  // Basic sanitation
  return preg_replace('/[\r\n\s]+/', '', $addr);
}

$__INGRESS_CMD = ingress_current_cmd();
$GLOBALS['INGRESS_CURRENT_CMD'] = $__INGRESS_CMD;
if (!empty($GLOBALS['INGRESS_CONFIG_ISSUES']['fatal']) && !ingress_is_diagnostics_request($__INGRESS_CMD)) {
  ingress_bootstrap_fail($GLOBALS['INGRESS_CONFIG_ISSUES']['fatal']);
}

// --- CORS & origin/referrer enforcement
// ===================== CORS / ORIGIN GUARD =====================
$origin  = $_SERVER['HTTP_ORIGIN'] ?? '';
$referer = $_SERVER['HTTP_REFERER'] ?? '';
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
  if ($origin && in_array($origin, $CFG['allowed_origins'], true)) {
    header("Access-Control-Allow-Origin: $origin");
    header('Access-Control-Allow-Headers: Content-Type, Accept, X-Requested-With, X-Form-Token');
    header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
    header('Access-Control-Allow-Credentials: true');
    header('Vary: Origin');
    header('Access-Control-Expose-Headers: X-Submission-Ref, X-RateLimit-Remaining, X-Duplicate');
  }
  exit;
}
if ($origin) {
  $ok = in_array($origin, $CFG['allowed_origins'], true);
  if (
    !$ok
    && strpos($origin, 'http://localhost:') === 0
    && in_array('http://localhost', $CFG['allowed_origins'], true)
  ) {
    $ok = true;
  }
  if (!$ok) json_fail(403, 'Origin not allowed');
  header("Access-Control-Allow-Origin: $origin");
  header('Access-Control-Allow-Credentials: true');
  header('Vary: Origin');
  header('Access-Control-Expose-Headers: X-Submission-Ref, X-RateLimit-Remaining, X-Duplicate');
}
if ($referer) {
  if (!is_referrer_allowed($referer, (array)$CFG['allowed_origins'])) json_fail(403, 'Bad referer');
}

// --- Basic payload-size guard
// ===================== PAYLOAD LIMIT =====================
$cl = (int)($_SERVER['CONTENT_LENGTH'] ?? 0);
log_event('request_start', ['method'=>$_SERVER['REQUEST_METHOD'] ?? '', 'cl'=>$cl, 'origin'=>$origin, 'referer'=>$referer]);
if ($cl > $CFG['max_bytes']) json_fail(413, 'Payload too large');

// ===================== VERSION (GET ?cmd=version) =====================
if (($_GET['cmd'] ?? '') === 'version') {
  // gated by extra_cmds; disabled by default
  extra_cmds_check('version');
  $file = __FILE__;
  echo json_encode([
    'ok' => true,
    'version' => (string)($CFG['version'] ?? ''),
    'php' => PHP_VERSION,
    'mtime' => @filemtime($file),
  ]);
  exit;
}

// ===================== HEALTH (GET ?cmd=health) — only when DEBUG enabled =====================
if ($__INGRESS_CMD === 'health') {
  extra_cmds_check('health');
  $okSqlite = false; $err='';
  try {
    $testDir = rtrim($CFG['storage_dir'], DIRECTORY_SEPARATOR);
    if (!is_dir($testDir)) { @mkdir($testDir, 0700, true); }
    $testPath = $testDir . DIRECTORY_SEPARATOR . '.wtest';
    @file_put_contents($testPath, 'ok');
    $okSqlite = file_exists($testPath);
    @unlink($testPath);
  } catch (Throwable $e) { $err=$e->getMessage(); }
  $issues = $GLOBALS['INGRESS_CONFIG_ISSUES'];
  $configOk = empty($issues['fatal']);
  echo json_encode([
    'ok' => ($okSqlite && $configOk),
    'debug' => true,
    'accept_payload' => $CFG['accept_payload'],
    'notify_targets' => $CFG['notify_targets'],
    'smtp' => [
      'host' => (string)$CFG['smtp']['host'],
      'port' => (int)$CFG['smtp']['port'],
      'secure' => (string)$CFG['smtp']['secure'],
      'auth' => (string)$CFG['smtp']['auth'],
      'helo' => (string)$CFG['smtp']['helo'],
    ],
    'sqlite_writable' => $okSqlite,
    'storage_dir' => $CFG['storage_dir'],
    'error' => $err ?: null,
    'config_ok' => $configOk,
    'config_issues' => $issues,
  ]);
  exit;
}

// ===================== CONFIG SELF-TEST (GET ?cmd=check) =====================
if ($__INGRESS_CMD === 'check') {
  extra_cmds_check('check');
  $errors = []; $warnings = []; $info = [];

  $issues = $GLOBALS['INGRESS_CONFIG_ISSUES'];
  foreach ($issues['fatal'] as $fatalIssue) {
    $errors[] = $fatalIssue;
  }
  foreach ($issues['warnings'] as $warnIssue) {
    $warnings[] = $warnIssue;
  }

  // Secret
  if (($CFG['secret'] ?? '') === 'CHANGE_ME_LONG_RANDOM') {
    $warnings[] = 'secret uses default value; set a long random secret';
  } elseif (strlen((string)$CFG['secret']) < 16) {
    $warnings[] = 'secret is short; use at least 16 characters';
  }

  // Origins
  if (empty($CFG['allowed_origins']) || !is_array($CFG['allowed_origins'])) {
    $warnings[] = 'allowed_origins is empty; set your site origins';
  }

  // Accept payload
  $ap = strtolower((string)($CFG['accept_payload'] ?? 'both'));
  if (!in_array($ap, ['json','form','both'], true)) {
    $errors[] = 'accept_payload must be json|form|both';
  }

  // Storage write
  $testDir = rtrim((string)$CFG['storage_dir'], DIRECTORY_SEPARATOR);
  try {
    if (!is_dir($testDir)) { @mkdir($testDir, 0700, true); }
    $testPath = $testDir . DIRECTORY_SEPARATOR . '.wtest';
    @file_put_contents($testPath, 'ok');
    $okSqlite = file_exists($testPath);
    @unlink($testPath);
    if (!$okSqlite) $errors[] = 'storage_dir not writable';
  } catch (Throwable $e) { $errors[] = 'storage_dir write failed: '.$e->getMessage(); }

  // Email target readiness
  $targets = parse_targets((string)($CFG['notify_targets'] ?? 'email'));
  if ($targets['email']) {
    $smtp = (array)($CFG['smtp'] ?? []);
    if (empty($smtp['host'])) $warnings[] = 'SMTP host not set (email target enabled)';
    if (empty($smtp['user'])) $warnings[] = 'SMTP user not set (email target enabled)';
    if (empty($smtp['port'])) $warnings[] = 'SMTP port not set (email target enabled)';
  }

  // JSON forward readiness
  if (!empty($CFG['json_forward_url'])) {
    if (empty($CFG['json_forward_secret'])) $warnings[] = 'json_forward_secret not set for JSON forward';
    if (!function_exists('curl_init')) $warnings[] = 'curl extension missing (required for JSON forward)';
  }

  // CAPTCHA readiness
  $cap = (array)($CFG['captcha'] ?? []);
  if (!empty($cap['enabled'])) {
    if (empty($cap['secret'])) $errors[] = 'captcha.secret is required when captcha.enabled=true';
    $prov = strtolower((string)($cap['provider'] ?? 'turnstile'));
    if (!in_array($prov, ['turnstile','hcaptcha','recaptcha_v3'], true)) $errors[] = 'captcha.provider invalid';
    if (!function_exists('curl_init')) $warnings[] = 'curl extension missing (required for CAPTCHA verification)';
  }

  // Built-in CAPTCHA sanity
  $bc = (array)($CFG['builtin_captcha'] ?? []);
  if (!empty($bc['enabled'])) {
    $min = (int)($bc['min'] ?? 1); $max = (int)($bc['max'] ?? 9);
    if ($min > $max) $errors[] = 'builtin_captcha.min must be <= max';
    $ops = (array)($bc['ops'] ?? ['+']);
    foreach ($ops as $op) { if (!in_array($op, ['+','-'], true)) { $errors[] = 'builtin_captcha.ops supports only + or -'; break; } }
  }

  // Extra cmds security
  $ex = (array)($CFG['extra_cmds'] ?? []);
  if (!empty($ex['enabled'])) {
    if (empty($ex['key']) && empty($ex['allow_ips'])) {
      $warnings[] = 'extra_cmds enabled without key or allow_ips; consider gating diagnostics';
    }
  }

  $ok = empty($errors);
  echo json_encode(['ok'=>$ok,'errors'=>$errors,'warnings'=>$warnings,'info'=>$info]);
  exit;
}

// ===================== SMTP PROBE (GET ?cmd=probe_smtp) — DEBUG ONLY =====================
function smtp_probe(array $smtp): array {
  $out = [
    'ok' => false,
    'stage' => 'init',
    'secure' => $smtp['secure'] ?? 'tls',
    'host' => $smtp['host'] ?? '',
    'port' => (int)($smtp['port'] ?? 587),
    'helo' => $smtp['helo'] ?? '',
    'caps' => [],
    'auth_pref' => $smtp['auth'] ?? 'auto',
    'auth_tried' => [],
    'auth_ok' => false,
    'error' => null,
    'from' => '',
  ];
  try {
    $res = ['ok'=>false,'error'=>''];
    // Build minimal emailCfg/to for reuse of connection pieces
    $host = (string)($smtp['host'] ?? '');
    $port = (int)($smtp['port'] ?? 587);
    $secure = strtolower((string)($smtp['secure'] ?? 'tls'));
    $timeout = (int)($smtp['timeout'] ?? 8);
    $auth = strtolower((string)($smtp['auth'] ?? 'auto'));
    $user = (string)($smtp['user'] ?? '');
    $pass = (string)($smtp['pass'] ?? '');
    $helo = trim((string)($smtp['helo'] ?? '')); if ($helo==='') $helo = gethostname() ?: 'localhost';

    $from = (string)($smtp['from'] ?? $user);
    $out['from'] = $from;

    $out['stage'] = 'connect';
    $opts = [ 'ssl' => [
      'verify_peer'       => (bool)($smtp['verify_peer'] ?? true),
      'verify_peer_name'  => (bool)($smtp['verify_peer_name'] ?? true),
      'allow_self_signed' => (bool)($smtp['allow_self_signed'] ?? false),
      'SNI_enabled'       => true,
      'peer_name'         => $host,
    ] ];
    $ctx = stream_context_create($opts);
    $remote = ($secure === 'ssl' ? 'ssl://' : '') . $host . ':' . $port;
    $errno = 0; $errstr = '';
    $fp = @stream_socket_client($remote, $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, $ctx);
    if (!$fp) { $out['error'] = "connect: $errstr ($errno)"; return $out; }
    stream_set_timeout($fp, $timeout);

    $out['stage'] = 'banner';
    smtp_expect($fp, [220], 'banner');

    $out['stage'] = 'ehlo';
    smtp_cmd($fp, "EHLO $helo\r\n");
    [, $resp] = smtp_expect($fp, [250], 'ehlo');
    $ehloResp = $resp;

    if ($secure === 'tls') {
      $out['stage'] = 'starttls';
      smtp_cmd($fp, "STARTTLS\r\n");
      smtp_expect($fp, [220], 'starttls');
      $cryptoMethod = defined('STREAM_CRYPTO_METHOD_TLS_CLIENT') ? STREAM_CRYPTO_METHOD_TLS_CLIENT : (STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT|STREAM_CRYPTO_METHOD_TLSv1_1_CLIENT|STREAM_CRYPTO_METHOD_TLSv1_0_CLIENT);
      if (!@stream_socket_enable_crypto($fp, true, $cryptoMethod)) { @fclose($fp); $out['error'] = 'starttls failed'; return $out; }
      // Re-EHLO after TLS
      $out['stage'] = 'ehlo-tls';
      smtp_cmd($fp, "EHLO $helo\r\n");
      [, $resp] = smtp_expect($fp, [250], 'ehlo-tls');
      $ehloResp = $resp;
    }

    // Parse caps
    if (isset($ehloResp) && preg_match('/^250[\-\s]+AUTH\s+(.+)$/mi', $ehloResp, $m)) {
      $out['caps'] = array_map('strtoupper', preg_split('/\s+/', trim($m[1])));
    }

    // Try auth (no mail send)
    $authPref = $auth;
    if ($authPref === 'auto') {
      if (in_array('LOGIN', $out['caps'], true)) $authPref = 'login'; elseif (in_array('PLAIN', $out['caps'], true)) $authPref = 'plain'; else $authPref = 'none';
    }
    $tryOrder = ($authPref === 'plain') ? ['plain','login'] : (($authPref === 'login') ? ['login','plain'] : []);

    foreach ($tryOrder as $method) {
      $out['auth_tried'][] = $method;
      try {
        if ($method === 'plain') {
          $attempts = [
            ['', $user, $pass, 'plain'],
            [$from ?: '', $user, $pass, 'plain-authzid-from'],
          ];
          $okp = false; $lastErrLocal = null;
          foreach ($attempts as [$az,$uc,$pw,$variant]) {
            try {
              $token = base64_encode("{$az}\0{$uc}\0{$pw}");
              smtp_cmd($fp, "AUTH PLAIN $token\r\n");
              smtp_expect($fp, [235], 'auth-plain');
              $okp = true; $out['auth_ok'] = true; $out['auth_variant'] = $variant; break;
            } catch (Throwable $ee) {
              $lastErrLocal = $ee->getMessage();
              $out['error'] = $lastErrLocal; // keep updating with the last error
            }
          }
          if (!$okp) { /* will fallthrough to possible LOGIN or end */ }
        } else { // login
          smtp_cmd($fp, "AUTH LOGIN\r\n");
          smtp_expect($fp, [334], 'auth-login-username');
          smtp_cmd($fp, base64_encode($user) . "\r\n");
          smtp_expect($fp, [334], 'auth-login-password');
          smtp_cmd($fp, base64_encode($pass) . "\r\n");
          smtp_expect($fp, [235], 'auth-login-done');
          $out['auth_ok'] = true; break;
        }
      } catch (Throwable $e) {
        $out['error'] = $e->getMessage();
      }
    }

    smtp_cmd($fp, "QUIT\r\n");
    @fclose($fp);
    $out['ok'] = ($out['error'] === null) || $out['auth_ok'];
    return $out;
  } catch (Throwable $e) {
    $out['error'] = $e->getMessage();
    return $out;
  }
}

function process_forward_queue(PDO $db, array $CFG): array {
  $max = (int)($CFG['queue_max_batch'] ?? 50);
  $processed=0; $sent=0; $failed=0; $items=[];
  try {
    $db->exec("CREATE TABLE IF NOT EXISTS forwards (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at INTEGER, ref TEXT, json TEXT, attempts INTEGER, last_error TEXT)");
    $stmt = $db->prepare("SELECT id, ref, json FROM forwards ORDER BY id ASC LIMIT ?");
    $stmt->bindValue(1, $max, PDO::PARAM_INT);
    $stmt->execute();
    $items = $stmt->fetchAll(PDO::FETCH_ASSOC);
  } catch (Throwable $e) {
    log_event('forward_queue_error', ['error'=>$e->getMessage()]);
    return ['ok'=>false,'processed'=>0,'sent'=>0,'failed'=>0,'error'=>$e->getMessage()];
  }
  foreach ($items as $row) {
    $processed++;
    $json = (string)$row['json']; $ref = (string)$row['ref'];
    $sig  = hash_hmac('sha256', $json, (string)$CFG['json_forward_secret']);
    $maxFR = max(0, (int)$CFG['forward_retries']);
    $okFwd=false; $lastErr=null; $codeF=0;
    for ($fa=0; $fa <= $maxFR; $fa++) {
      $ch = curl_init($CFG['json_forward_url']);
      curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => ['Content-Type: application/json','Accept: application/json','X-Signature: '.$sig],
        CURLOPT_POSTFIELDS => $json,
        CURLOPT_TIMEOUT => (int)$CFG['forward_timeout'],
        CURLOPT_CONNECTTIMEOUT => (int)$CFG['forward_connect'],
      ]);
      $resp = curl_exec($ch);
      $err  = curl_error($ch);
      $info = curl_getinfo($ch);
      $codeF = (int)($info['http_code'] ?? 0);
      curl_close($ch);
      $transient = (!empty($err) || ($codeF >= 500 && $codeF < 600) || $codeF === 0);
      if (!$transient && $codeF >= 200 && $codeF < 300) { $okFwd = true; break; }
      if ($fa < $maxFR && $transient) { usleep(((int)$CFG['forward_retry_sleep_ms'] * ($fa + 1)) * 1000); } else { $lastErr = $err ?: ('http '.$codeF); break; }
    }
    if ($okFwd) {
      $sent++; $db->prepare("DELETE FROM forwards WHERE id = ?")->execute([$row['id']]);
    } else {
      $failed++; $db->prepare("UPDATE forwards SET last_error = ? WHERE id = ?")->execute([(string)$lastErr, $row['id']]);
    }
  }
  return ['ok'=>true,'processed'=>$processed,'sent'=>$sent,'failed'=>$failed];
}


// --- CLI helper: flush queued forwards
if (PHP_SAPI === 'cli') {
  $argv0 = $argv[0] ?? '';
  $cmd   = $argv[1] ?? '';
  if ($cmd === 'flush-forwards') {
    // open DB path like in rate-limit section
    $storageDir = rtrim($CFG['storage_dir'], DIRECTORY_SEPARATOR);
    if (!is_dir($storageDir)) { @mkdir($storageDir, 0700, true); }
    if (!is_writable($storageDir)) { $storageDir = __DIR__; }
    if (!is_dir($storageDir)) { @mkdir($storageDir, 0700, true); }
    $nameFile = $storageDir . DIRECTORY_SEPARATOR . $CFG['db_name_file'];
    $dbname = file_exists($nameFile) ? trim((string)@file_get_contents($nameFile)) : '';
    if ($dbname === '') { fwrite(STDOUT, "No queue DB found\n"); exit(0); }
    $db_path = $storageDir . DIRECTORY_SEPARATOR . $dbname;
    try {
      $db = new PDO('sqlite:' . $db_path);
      $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    } catch (Throwable $e) {
      fwrite(STDERR, "DB open failed: ".$e->getMessage()."\n");
      exit(1);
    }
    $res = process_forward_queue($db, $CFG);
    fwrite(STDOUT, sprintf("processed=%d sent=%d failed=%d\n", (int)($res['processed']??0), (int)($res['sent']??0), (int)($res['failed']??0)));
    exit(0);
  } elseif ($cmd === 'purge-old') {
    // Purge old submissions/forwards based on retention config
    $daysSubs = (int)($CFG['retention_days'] ?? 90);
    $daysFwd  = (int)($CFG['forward_retention_days'] ?? 14);
    $now = time();
    $cutSubs = $now - max(0,$daysSubs) * 86400;
    $cutFwd  = $now - max(0,$daysFwd) * 86400;
    // open DB path like in rate-limit section
    $storageDir = rtrim($CFG['storage_dir'], DIRECTORY_SEPARATOR);
    if (!is_dir($storageDir)) { @mkdir($storageDir, 0700, true); }
    if (!is_writable($storageDir)) { $storageDir = __DIR__; }
    if (!is_dir($storageDir)) { @mkdir($storageDir, 0700, true); }
    $nameFile = $storageDir . DIRECTORY_SEPARATOR . $CFG['db_name_file'];
    $dbname = file_exists($nameFile) ? trim((string)@file_get_contents($nameFile)) : '';
    if ($dbname === '') { fwrite(STDOUT, "No DB found\n"); exit(0); }
    $db_path = $storageDir . DIRECTORY_SEPARATOR . $dbname;
    try {
      $db = new PDO('sqlite:' . $db_path);
      $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    } catch (Throwable $e) {
      fwrite(STDERR, "DB open failed: ".$e->getMessage()."\n");
      exit(1);
    }
    $subsPurged=0; $fwdPurged=0; $rlPurged=0;
    try {
      $st = $db->prepare("DELETE FROM submissions WHERE created_at < ?");
      $st->execute([$cutSubs]);
      $subsPurged = $db->query("SELECT changes()")->fetchColumn();
    } catch (Throwable $e) { /* ignore */ }
    try {
      $db->exec("CREATE TABLE IF NOT EXISTS forwards (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at INTEGER, ref TEXT, json TEXT, attempts INTEGER, last_error TEXT)");
      $st = $db->prepare("DELETE FROM forwards WHERE created_at < ?");
      $st->execute([$cutFwd]);
      $fwdPurged = $db->query("SELECT changes()")->fetchColumn();
    } catch (Throwable $e) { /* ignore */ }
    try {
      $st = $db->prepare("DELETE FROM ratelimit WHERE ts < ?");
      $st->execute([$now - (int)($CFG['rate_limit']['window_sec'] ?? 300)]);
      $rlPurged = $db->query("SELECT changes()")->fetchColumn();
    } catch (Throwable $e) { /* ignore */ }
    fwrite(STDOUT, sprintf("purged submissions=%d forwards=%d ratelimit=%d\n", (int)$subsPurged, (int)$fwdPurged, (int)$rlPurged));
    exit(0);
  } elseif ($cmd === 'purge-logs') {
    $path = (string)($CFG['debug_log'] ?? '');
    if ($path === '') { fwrite(STDOUT, "No debug_log configured\n"); exit(0); }
    if (is_file($path)) {
      @unlink($path);
      if (!file_exists($path)) { fwrite(STDOUT, "debug log removed\n"); }
      else { fwrite(STDERR, "failed to remove debug log\n"); exit(1); }
    } else {
      fwrite(STDOUT, "debug log not found\n");
    }
    exit(0);
  } elseif ($cmd === 'rotate-logs') {
    $path = (string)($CFG['debug_log'] ?? '');
    if ($path === '') { fwrite(STDOUT, "No debug_log configured\n"); exit(0); }
    if (!is_file($path)) { fwrite(STDOUT, "debug log not found\n"); exit(0); }
    $maxKib = isset($argv[2]) ? max(1, (int)$argv[2]) : (int)($CFG['log_rotate_max_kib'] ?? 256);
    $maxBytes = $maxKib * 1024;
    $size = (int)@filesize($path);
    if ($size <= 0) { fwrite(STDOUT, "empty log\n"); exit(0); }
    if ($size <= $maxBytes) { fwrite(STDOUT, "no rotation needed (size=".$size.")\n"); exit(0); }
    $fp = @fopen($path, 'rb');
    if (!$fp) { fwrite(STDERR, "failed to open log for read\n"); exit(1); }
    if (@fseek($fp, $size - $maxBytes, SEEK_SET) !== 0) { @fclose($fp); fwrite(STDERR, "seek failed\n"); exit(1); }
    $tail = @stream_get_contents($fp, $maxBytes);
    @fclose($fp);
    if ($tail === false) { fwrite(STDERR, "read failed\n"); exit(1); }
    // Try to start at a newline boundary
    $nlPos = strpos($tail, "\n");
    if ($nlPos !== false && $nlPos + 1 < strlen($tail)) {
      $tail = substr($tail, $nlPos + 1);
    }
    $banner = "[log rotated to last ".$maxKib." KiB on ".gmdate('c')."]\n";
    $new = $banner . $tail;
    $ok = @file_put_contents($path, $new, LOCK_EX);
    if ($ok === false) { fwrite(STDERR, "write failed\n"); exit(1); }
    fwrite(STDOUT, "rotated, new_size=".((int)@filesize($path))." bytes\n");
    exit(0);
  }
}


if (($_GET['cmd'] ?? '') === 'probe_smtp') {
  extra_cmds_check('probe_smtp');
  // Allow overrides via query for diagnostics
  $smtp = $CFG['smtp'];
  $mapStr = ['host','secure','auth','helo','user','pass','from'];
  foreach ($mapStr as $k) { if (isset($_GET[$k])) $smtp[$k] = (string)$_GET[$k]; }
  if (isset($_GET['port'])) $smtp['port'] = (int)$_GET['port'];
  foreach (['verify_peer','verify_peer_name','allow_self_signed'] as $b) {
    if (isset($_GET[$b])) $smtp[$b] = ($_GET[$b] === '1' || strtolower($_GET[$b]) === 'true');
  }
  $res = smtp_probe($smtp);
  log_event('smtp_probe', ['result' => ['ok'=>$res['ok'], 'stage'=>$res['stage'], 'caps'=>$res['caps'], 'auth_ok'=>$res['auth_ok']]]);
  echo json_encode(['ok'=>true,'probe'=>$res]);
  exit;
}

if (($_GET['cmd'] ?? '') === 'flush_queue') {
  extra_cmds_check('flush_queue');
  if (empty($CFG['forward_queue_enabled'])) json_fail(403, 'Queue disabled');

  // open DB path like in rate-limit section
  $storageDir = rtrim($CFG['storage_dir'], DIRECTORY_SEPARATOR);
  if (!is_dir($storageDir)) { @mkdir($storageDir, 0700, true); }
  if (!is_writable($storageDir)) { $storageDir = __DIR__; }
  if (!is_dir($storageDir)) { @mkdir($storageDir, 0700, true); }
  $nameFile = $storageDir . DIRECTORY_SEPARATOR . $CFG['db_name_file'];
  $dbname = file_exists($nameFile) ? trim((string)@file_get_contents($nameFile)) : '';
  if ($dbname === '') { echo json_encode(['ok'=>true,'processed'=>0,'sent'=>0,'failed'=>0]); exit; }
  $db_path = $storageDir . DIRECTORY_SEPARATOR . $dbname;
  try { $db = new PDO('sqlite:' . $db_path); $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION); }
  catch (Throwable $e) { json_fail(500, 'DB open failed'); }

  $res = process_forward_queue($db, $CFG);
  echo json_encode(['ok'=>$res['ok'], 'processed'=>$res['processed'], 'sent'=>$res['sent'], 'failed'=>$res['failed']]);
  exit;
}

// ===================== OPTIONAL QUEUE AUTO-FLUSH ON PLAIN GET =====================
// --- Offers a tiny "cronless" safety net when enabled; remains off by default
if ($_SERVER['REQUEST_METHOD'] === 'GET'
    && empty($_GET['cmd'])
    && !empty($CFG['forward_queue_enabled'])
    && !empty($CFG['queue_flush_on_get'])) {

  // Open DB path like in rate-limit section
  $storageDir = rtrim($CFG['storage_dir'], DIRECTORY_SEPARATOR);
  if (!is_dir($storageDir)) { @mkdir($storageDir, 0700, true); }
  if (!is_writable($storageDir)) { $storageDir = __DIR__; }
  if (!is_dir($storageDir)) { @mkdir($storageDir, 0700, true); }

  $nameFile = $storageDir . DIRECTORY_SEPARATOR . $CFG['db_name_file'];
  $dbname = file_exists($nameFile) ? trim((string)@file_get_contents($nameFile)) : '';
  if ($dbname !== '') {
    $db_path = $storageDir . DIRECTORY_SEPARATOR . $dbname;
    try {
      $db = new PDO('sqlite:' . $db_path);
      $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
      $res = process_forward_queue($db, $CFG);
      log_event('auto_flush_queue', [
        'processed' => $res['processed'] ?? 0,
        'sent'      => $res['sent'] ?? 0,
        'failed'    => $res['failed'] ?? 0
      ]);
    } catch (Throwable $e) {
      log_event('auto_flush_queue_error', ['error'=>$e->getMessage()]);
    }
  }

  // Silent 204 so normal GETs (e.g., health pings) don't break UIs/images
  if (!headers_sent()) http_response_code(204);
  exit;
}

// --- CSRF token mint for forms
// ===================== TOKEN MINT (GET ?cmd=token) =====================
if (($_GET['cmd'] ?? '') === 'token') {
  $ts = time(); $rnd = bin2hex(random_bytes(16));
  $data = $ts . '.' . $rnd; $sig = b64u(hmac($data, $CFG['secret']));
  $token = b64u($data . '.' . $sig);
  $secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
  setcookie('form_token', $token, [
    'expires'  => $ts + $CFG['token_max_age'],
    'path'     => '/',
    'secure'   => $secure,
    'httponly' => true,
    'samesite' => 'Lax',
  ]);
  log_event('token_mint', ['expires'=>$ts + $CFG['token_max_age'], 'secure'=>$secure]);
  $resp = ['ok'=>true,'token'=>$token];
  if (!empty($CFG['builtin_captcha']['enabled'])) {
    $cap = builtin_captcha_mint((array)$CFG['builtin_captcha'], (string)$CFG['secret']);
    $resp['captcha_q'] = $cap['q'];
    $resp['captcha_token'] = $cap['token'];
  }
  echo json_encode($resp);
  exit;
}

// --- Submission entrypoint
// ===================== ONLY POST FOR SUBMISSIONS =====================
if ($_SERVER['REQUEST_METHOD'] !== 'POST') json_fail(405, 'Method not allowed');
$clientInfo = ingress_resolve_client_ip($CFG);
$GLOBALS['INGRESS_CLIENT_INFO'] = $clientInfo;
$ip = $clientInfo['ip'] ?? ($_SERVER['REMOTE_ADDR'] ?? '');
if ($ip === '' && isset($clientInfo['remote_addr'])) {
  $ip = (string)$clientInfo['remote_addr'];
}
if (!ingress_ip_is_valid($ip) && isset($clientInfo['remote_addr']) && ingress_ip_is_valid((string)$clientInfo['remote_addr'])) {
  $ip = (string)$clientInfo['remote_addr'];
}
$_SERVER['INGRESS_CLIENT_IP'] = $ip;
$ua = $_SERVER['HTTP_USER_AGENT'] ?? '';

// --- Content-type negotiation
// ===================== ACCEPT JSON OR FORM-ENCODED =====================
$mode   = strtolower((string)($CFG['accept_payload'] ?? 'both'));
$ctype  = strtolower($_SERVER['CONTENT_TYPE'] ?? '');
$payload = [];

if ($mode === 'json') {
  if (strpos($ctype, 'application/json') === false) json_fail(415, 'Only application/json accepted');
  $raw = file_get_contents('php://input');
  if (($raw === '' || $raw === false) && isset($_SERVER['INGRESS_TEST_BODY'])) {
    $raw = (string)$_SERVER['INGRESS_TEST_BODY'];
  }
  $payload = json_decode($raw ?: '[]', true);
  if (!is_array($payload)) json_fail(400, 'Invalid JSON');
}
elseif ($mode === 'form') {
  if (strpos($ctype, 'application/json') !== false) json_fail(415, 'JSON not accepted');
  $payload = $_POST; // supports x-www-form-urlencoded & multipart
}
else { // both
  if (strpos($ctype, 'application/json') !== false) {
    $raw = file_get_contents('php://input');
    if (($raw === '' || $raw === false) && isset($_SERVER['INGRESS_TEST_BODY'])) {
      $raw = (string)$_SERVER['INGRESS_TEST_BODY'];
    }
    $payload = json_decode($raw ?: '[]', true);
    if (!is_array($payload)) json_fail(400, 'Invalid JSON');
  } else {
    $payload = $_POST; // supports x-www-form-urlencoded & multipart
  }
}

log_event('payload_parsed', [
  'mode'=>$mode, 'ctype'=>$ctype,
  'fields'=> is_array($payload) ? count($payload) : 0
]);

// Merge UTM from query string (if any)
parse_str($_SERVER['QUERY_STRING'] ?? '', $qs);
foreach (['utm_source','utm_medium','utm_campaign'] as $k) {
  if (!isset($payload[$k]) && isset($qs[$k])) $payload[$k] = $qs[$k];
}

// --- Honeypots, dwell-time, and double-submit cookie verification
// ===================== ANTI-BOT / CSRF =====================
// Honeypot
if (!empty($payload['website'])) json_fail(400, 'Bot detected');
if (!empty($payload['fax'])) json_fail(400, 'Bot detected');
// Dwell
$dwell = isset($payload['dwell_ms']) ? (int)$payload['dwell_ms'] : 0;
if ($dwell > 0 && $dwell < $CFG['min_dwell_ms']) json_fail(400, 'Please try again');
// Token (posted token must match cookie and be fresh)
$posted_token = (string)($payload['token'] ?? ($_SERVER['HTTP_X_FORM_TOKEN'] ?? ''));
$cookie_token = $_COOKIE['form_token'] ?? '';
// No-JS fallback: if the hidden `token` wasn't populated, accept the cookie token as the posted token
if ($posted_token === '' && $cookie_token !== '') { $posted_token = $cookie_token; }
if (!$posted_token || !$cookie_token || !heq($posted_token, $cookie_token)) json_fail(400, 'Token invalid');
$rawt = b64u_dec($posted_token);
if (!$rawt) json_fail(400, 'Token corrupt');
$parts = explode('.', $rawt, 3);
if (count($parts) !== 3) json_fail(400, 'Token corrupt');
[$ts_str, $rnd, $sig_in] = $parts;
$data = $ts_str . '.' . $rnd;
if (!heq(b64u(hmac($data, $CFG['secret'])), $sig_in)) json_fail(400, 'Bad signature');
$age = time() - (int)$ts_str; if ($age < $CFG['token_min_age'] || $age > $CFG['token_max_age']) json_fail(400, 'Token expired');
log_event('csrf_ok', ['age'=>$age]);
if (!empty($CFG['require_ts_echo'])) {
  $tsEcho = isset($payload['ts_echo']) ? (int)$payload['ts_echo'] : (isset($payload['token_ts']) ? (int)$payload['token_ts'] : 0);
  if (!$tsEcho || $tsEcho !== (int)$ts_str) {
    json_fail(400, 'Bad token echo');
  }
}
// Optional site_key allow-list
if (!empty($CFG['site_keys'])) {
  $sk = isset($payload['site_key']) ? (string)$payload['site_key'] : '';
  if ($sk === '' || !in_array($sk, (array)$CFG['site_keys'], true)) {
    json_fail(400, 'Bad site key');
  }
}

// CAPTCHA (optional)
try {
  $capCfg = (array)($CFG['captcha'] ?? []);
  if (!empty($capCfg['enabled'])) {
    // Accept multiple common field names from providers
    $tok = (string)($payload['captcha_token']
      ?? ($payload['cf-turnstile-response'] ?? ($payload['cf_turnstile_response'] ?? null))
      ?? ($payload['h-captcha-response'] ?? null)
      ?? ($payload['g-recaptcha-response'] ?? '')
    );
    if ($tok === '') { json_fail(400, 'Captcha required'); }
    $vr = verify_captcha($capCfg, $tok, $ip);
    log_event('captcha_verify', ['ok'=>$vr['ok'] ?? false, 'provider'=>$vr['provider'] ?? '', 'score'=>$vr['score'] ?? null, 'error'=>$vr['error'] ?? null]);
    if (empty($vr['ok'])) json_fail(400, 'Captcha failed');
  }
} catch (Throwable $e) { log_event('captcha_error', ['error'=>$e->getMessage()]); json_fail(400, 'Captcha error'); }

// Built-in CAPTCHA (optional)
if (!empty($CFG['builtin_captcha']['enabled'])) {
  $ans = isset($payload['captcha_answer']) ? (string)$payload['captcha_answer'] : '';
  $tok = isset($payload['captcha_token']) ? (string)$payload['captcha_token'] : '';
  if ($ans === '' || $tok === '') { json_fail(400, 'Captcha required'); }
  if (!builtin_captcha_check($tok, $ans, (string)$CFG['secret'])) { json_fail(400, 'Captcha failed'); }
}

// --- IP throttling and storage bootstrap
// ===================== RATE LIMIT (SQLite) =====================
// Prepare storage dir outside webroot; create random DB name once and reuse
$storageDir = rtrim($CFG['storage_dir'], DIRECTORY_SEPARATOR);
if (!is_dir($storageDir)) { @mkdir($storageDir, 0700, true); }
if (!is_writable($storageDir)) { $storageDir = __DIR__; }
if (!is_dir($storageDir)) { @mkdir($storageDir, 0700, true); }

$nameFile = $storageDir . DIRECTORY_SEPARATOR . $CFG['db_name_file'];
if (!file_exists($nameFile)) {
  $dbname = '.db_' . bin2hex(random_bytes(16)) . '.sqlite';
  @file_put_contents($nameFile, $dbname);
  @chmod($nameFile, 0600);
} else {
  $dbname = trim((string)@file_get_contents($nameFile));
  if ($dbname === '') { $dbname = '.db_' . bin2hex(random_bytes(16)) . '.sqlite'; @file_put_contents($nameFile, $dbname); }
}
$db_path = $storageDir . DIRECTORY_SEPARATOR . $dbname;

try {
  $db = new PDO('sqlite:' . $db_path);
  @chmod($db_path, 0600);
  $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
  $db->exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA temp_store=MEMORY;");
  $db->exec("PRAGMA busy_timeout=3000;");
  $db->exec("CREATE TABLE IF NOT EXISTS ratelimit (ip TEXT, ts INTEGER)");
  $db->exec("CREATE TABLE IF NOT EXISTS submissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at INTEGER,
    ip TEXT, user_agent TEXT,
    payload_json TEXT
  )");
  // Ensure new columns exist (ignore errors if already present)
  try { $db->exec("ALTER TABLE submissions ADD COLUMN ref TEXT"); } catch (Throwable $e) { /* no-op */ }
  try { $db->exec("ALTER TABLE submissions ADD COLUMN dedupe_key TEXT"); } catch (Throwable $e) { /* no-op */ }
  try { $db->exec("CREATE INDEX IF NOT EXISTS idx_submissions_dedupe ON submissions(dedupe_key, created_at)"); } catch (Throwable $e) { /* no-op */ }

  $now = time();
  $db->prepare("DELETE FROM ratelimit WHERE ts < ?")->execute([$now - $CFG['rate_limit']['window_sec']]);
  $stmt = $db->prepare("SELECT COUNT(*) FROM ratelimit WHERE ip = ? AND ts >= ?");
  $stmt->execute([$ip, $now - $CFG['rate_limit']['window_sec']]);
  $recent = (int)$stmt->fetchColumn();
  if ($recent >= $CFG['rate_limit']['max_per_ip']) json_fail(429, 'Too many submissions');
  $db->prepare("INSERT INTO ratelimit(ip, ts) VALUES(?, ?)")->execute([$ip, $now]);
  $__rate_remaining = max(0, (int)$CFG['rate_limit']['max_per_ip'] - $recent - 1);
  log_event('db_ok', ['db'=>$db_path]);
} catch (Throwable $e){
  log_event('db_error', ['error'=>$e->getMessage()]);
  json_fail(500, 'Storage error (rate limit)');
}

// --- Schema-less field discovery & validation using $CFG knobs
// ===================== BASIC VALIDATION (friendly; schema-less) =====================
$clean = $payload; // copy for storage/email

if (is_array($clean) && count($clean) > (int)$CFG['max_fields']) {
  json_fail(400, 'Too many fields');
}

// Try to locate typical fields
$name  = '';
if (isset($clean['name'])) $name = trim((string)$clean['name']);
elseif (isset($clean['full_name'])) $name = trim((string)$clean['full_name']);
$email = '';
foreach ($clean as $k=>$v){ if (preg_match('/email/i', (string)$k) && filter_var((string)$v, FILTER_VALIDATE_EMAIL)) { $email = (string)$v; break; } }
$phone = isset($clean['phone']) ? trim((string)$clean['phone']) : '';
$message = isset($clean['message']) ? trim((string)$clean['message']) : '';
if ($message === '' && isset($clean['notes'])) { $message = trim((string)$clean['notes']); }

// Consent
$consent_ok = false;
if (isset($clean['consent_text'])) { $consent_ok = (strtolower(trim((string)$clean['consent_text'])) === 'agree'); }
elseif (isset($clean['consent'])) { $consent_ok = filter_var($clean['consent'], FILTER_VALIDATE_BOOLEAN); }

$minName  = (int)$CFG['min_name_chars'];
$minEmail = (int)$CFG['min_email_chars'];
$minPhone = (int)$CFG['min_phone_chars'];
$minMsg   = (int)$CFG['min_message_chars'];
$allowLinks = !empty($CFG['allow_links_in_message']);

if ($name === '' || strlen($name) < $minName) {
  json_fail(400, 'Name too short (min '.$minName.' chars)');
}
if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) < $minEmail) {
  json_fail(400, 'Valid email required (min '.$minEmail.' chars)');
}
// Optional email domain policy
if ($email !== '') {
  $at = strrchr($email, '@');
  $domain = $at !== false ? strtolower(substr($at, 1)) : '';
  $allow = (array)($CFG['email_domain_allow'] ?? []);
  $block = (array)($CFG['email_domain_block'] ?? []);
  if (!empty($allow) && $domain !== '' && !in_array($domain, array_map('strtolower', $allow), true)) {
    json_fail(400, 'Email domain not permitted');
  }
  if (!empty($block) && $domain !== '' && in_array($domain, array_map('strtolower', $block), true)) {
    json_fail(400, 'Email domain blocked');
  }
}
if ($phone === '' || strlen(preg_replace('/\\s+/', '', $phone)) < $minPhone) {
  json_fail(400, 'Phone required ('.$minPhone.'+ chars)');
}
if ($message === '' || strlen($message) < $minMsg) {
  json_fail(400, 'Message too short (min '.$minMsg.' chars)');
}
if (!$allowLinks) {
  // Block common protocols: http, https, ftp, mailto, ssh, telnet, scp, smb
  if (preg_match('/\\b(?:https?:\\/\\/|ftp:\\/\\/|mailto:|ssh:\\/\\/|telnet:\\/\\/|scp:\\/\\/|smb:\\/\\/)/i', $message)) {
    json_fail(400, 'Links are not allowed in the message');
  }
}
// Keyword denylist (optional; simple substring match)
$denylist = (array)($CFG['keyword_denylist'] ?? []);
if (!empty($denylist)) {
  $fieldsForCheck = (array)($CFG['keyword_denylist_fields'] ?? []);
  $aggregate = '';
  foreach ($fieldsForCheck as $fk) {
    if (isset($clean[$fk]) && is_scalar($clean[$fk])) { $aggregate .= ' ' . (string)$clean[$fk]; }
  }
  $aggLower = lc_str($aggregate);
  foreach ($denylist as $kw) {
    $kw = (string)$kw; if ($kw === '') continue;
    if (ci_contains($aggLower, lc_str($kw))) {
      log_event('denylist_block', ['keyword'=>$kw]);
      json_fail(400, 'Contains blocked keywords');
    }
  }
}
if (!$consent_ok) json_fail(400, 'Consent required');

// Generate submission ref early (may be reused for dedupe save)
$ref = strtoupper(bin2hex(random_bytes(3))) . '-' . dechex(time());

// Compute dedupe key (email + normalized message)
$normEmail = normalize_email_for_key($email);
$normMsg   = normalize_text($message);
$dedupeKey = hash('sha256', $normEmail . "\n" . $normMsg);

// --- Duplicate suppression window
// ===================== DEDUPE (same email+message within window) =====================
try {
  $win = (int)$CFG['dedupe_window_sec'];
  if ($win > 0) {
    $stmt = $db->prepare("SELECT ref, created_at FROM submissions WHERE dedupe_key = ? AND created_at >= ? ORDER BY created_at DESC LIMIT 1");
    $stmt->execute([$dedupeKey, time() - $win]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if ($row && !empty($row['ref'])) {
      $ref = (string)$row['ref'];
      log_event('dedupe_hit', ['ref'=>$ref, 'window_sec'=>$win]);
      if (!headers_sent()) {
        if (isset($__rate_remaining)) header('X-RateLimit-Remaining: ' . (string)$__rate_remaining);
        header('X-Submission-Ref: ' . $ref);
        header('X-Duplicate: 1');
      }
      echo json_encode(['ok'=>true,'ref'=>$ref,'duplicate'=>true]);
      exit;
    }
    log_event('dedupe_check', ['window_sec'=>$win]);
  }
} catch (Throwable $e) {
  log_event('dedupe_error', ['error'=>$e->getMessage()]);
}

// --- Persist the cleaned submission
// ===================== SAVE SUBMISSION =====================
try {
  $ins = $db->prepare("INSERT INTO submissions (created_at, ip, user_agent, payload_json, ref, dedupe_key) VALUES (?, ?, ?, ?, ?, ?)");
  $ins->execute([time(), $ip, $ua, json_encode($clean, JSON_UNESCAPED_UNICODE), $ref, $dedupeKey]);
  $savedId = null;
  try { if ($db) { $savedId = $db->lastInsertId(); } } catch (Throwable $e) { $savedId = null; }
  log_event('saved_submission', ['id' => $savedId]);
} catch (Throwable $e){
  log_event('save_error', ['error'=>$e->getMessage()]);
  // continue; email/forward still proceed
}

// Optionally respond to client before running notifications — only if FastCGI async is available
$__responded = false;
$__async = (!empty($CFG['async_notify']) && $CFG['async_notify'] !== '0');
$__can_async = function_exists('fastcgi_finish_request');
if ($__async && $__can_async) {
  if (!headers_sent()) {
    if (isset($__rate_remaining)) header('X-RateLimit-Remaining: ' . (string)$__rate_remaining);
    header('X-Submission-Ref: ' . $ref);
  }
  header('X-Duplicate: 0');
  respond_now(['ok'=>true,'ref'=>$ref]);
  log_event('responded_async', ['ref'=>$ref]);
  $__responded = true;
}

// --- Delivery pipeline (SMTP + JSON forward)
// ===================== NOTIFICATIONS (configurable: email and/or n8n) =====================
$targets = parse_targets((string)$CFG['notify_targets']);

// Subject safety
$subject_offer = sanitize_header((string)($clean['offer'] ?? $clean['cta'] ?? 'General'));
$topic = '';
foreach (['topic','service','category','type','interest','department'] as $tk) {
  if (!empty($clean[$tk])) { $topic = sanitize_header((string)$clean[$tk]); break; }
}
$topicPrefix = $topic !== '' ? '['.$topic.'] ' : '';
$subject = $topicPrefix . $CFG['email']['subject_prefix'] . $subject_offer . ' [' . $ref . ']';

// Shared email body (generic, human-friendly)
$lines = [];
$lines[] = 'New enquiry (email delivery)';
$lines[] = 'Ref: ' . $ref;
$lines[] = '';

// Build a generic view of submitted fields
$kv = is_array($clean) ? $clean : [];

// Exclude purely technical fields from the main listing
$exclude = ['token','form_token','website','fax'];

// Helper to labelize keys (snake/camel → Title Case)
$labelize = function(string $k): string {
  $k = preg_replace('/([a-z])([A-Z])/', '$1 $2', $k); // camel → words
  $k = str_replace(['_','-'], ' ', (string)$k);
  $k = preg_replace('/\s+/', ' ', trim($k));
  return ucwords($k);
};
// Helper to stringify values
$str = function($v): string {
  if (is_bool($v)) return $v ? 'Yes' : 'No';
  if (is_scalar($v)) return (string)$v;
  return json_encode($v, JSON_UNESCAPED_UNICODE);
};

// Detect common fields (but don't require them)
$used = [];
// Name
if (!empty($name)) { $lines[] = 'Name: ' . $name; $used['name']=true; $used['full_name']=true; }
// Email
if (!empty($email)) {
  $lines[] = 'Email: ' . $email;
  foreach ($kv as $k=>$v){ if (preg_match('/email/i',$k)) { $used[$k]=true; }}
}
// Phone
if (!empty($phone)) {
  $lines[] = 'Phone: ' . $phone;
  foreach (['phone','mobile','cell','tel','telephone'] as $kk){ $used[$kk]=true; }
}
// Company-like
foreach (['company','organisation','organization','business','brand'] as $ck) {
  if (isset($kv[$ck]) && $kv[$ck] !== '') { $lines[] = 'Company: ' . $str($kv[$ck]); $used[$ck]=true; break; }
}
// Job-title-like
foreach (['job_title','job','role','title','position'] as $jk) {
  if (isset($kv[$jk]) && $kv[$jk] !== '') { $lines[] = 'Job Title: ' . $str($kv[$jk]); $used[$jk]=true; break; }
}
// VAT registered (normalize yes/no if boolean-like)
foreach (['vat_registered','vatreg'] as $vk) {
  if (array_key_exists($vk, $kv)) {
    $val = $kv[$vk];
    $valNorm = is_bool($val) ? ($val ? 'Yes' : 'No') : $str($val);
    $lines[] = 'VAT Registered: ' . $valNorm; $used[$vk]=true; break;
  }
}

// Message-like (render as a block)
$msgKey = null; $msgVal = '';
foreach ($kv as $k=>$v) {
  if (preg_match('/^(message|notes|enquiry|inquiry|description|request)$/i', $k)) { $msgKey=$k; $msgVal=$str($v); break; }
}

// Consent (text/checkbox style)
foreach (['consent_text','consent'] as $ckey) {
  if (isset($kv[$ckey]) && $kv[$ckey] !== '') { $lines[] = 'Consent: ' . $str($kv[$ckey]); $used[$ckey]=true; break; }
}

$lines[] = '';

if ($msgKey !== null) {
  $lines[] = 'Message:';
  $lines[] = (string)$msgVal;
  $used[$msgKey]=true;
  $lines[] = '';
}

// Split remaining fields into meta-ish and other
$meta = []; $other = [];
foreach ($kv as $k=>$v) {
  if (isset($used[$k])) continue;
  if (in_array($k, $exclude, true)) continue;
  $isMeta = preg_match('/^(utm_|page_url$|referrer$|site_key$|cta$|dwell|consent_)/i', $k) === 1;
  if ($isMeta) {
    $meta[$k] = $v;
  } else {
    $other[$k] = $v;
  }
}

// Other submitted fields (alphabetical for predictability)
if (!empty($other)) {
  $lines[] = 'Other submitted fields';
  $lines[] = '----------------------';
  ksort($other, SORT_NATURAL|SORT_FLAG_CASE);
  foreach ($other as $k=>$v) { $lines[] = $labelize($k) . ': ' . $str($v); }
  $lines[] = '';
}

// Submission meta (alphabetical, generic)
if (!empty($meta)) {
  $lines[] = 'Submission meta';
  $lines[] = '----------------';
  ksort($meta, SORT_NATURAL|SORT_FLAG_CASE);
  foreach ($meta as $k=>$v) { $lines[] = $labelize($k) . ': ' . $str($v); }
  $lines[] = '';
}

$lines[] = 'IP: ' . $ip;
$lines[] = 'UA: ' . $ua;
$lines[] = 'Time: ' . gmdate('c') . ' (UTC)';

$body = implode("\n", $lines);

// EMAIL (if enabled)
if ($targets['email']) {
  $replyTo = $email;
  $fromAddr = sanitize_header((string)$CFG['smtp']['user']);
  log_event('from_enforced', ['from'=>$fromAddr]);
  $sent = false; $lastErr = null;

  if (!empty($CFG['smtp']['host'])) {
    $smtpParams = $CFG['smtp'];
    $smtpParams['timeout'] = (int)$CFG['smtp_timeout'];
    $maxRetries = max(0, (int)$CFG['smtp_retries']);

    $buildVariants = function(array $p) use ($CFG) {
      $v = [];
      $sec = strtolower((string)($p['secure'] ?? 'tls'));
      if ($sec === 'tls') {
        $v[] = ['secure'=>'tls','port'=>$p['port'] ?? 587];
        if (!empty($CFG['smtp_fallback'])) { $v[] = ['secure'=>'ssl','port'=>465]; $v[] = ['secure'=>'none','port'=>25]; }
      } elseif ($sec === 'ssl') {
        $v[] = ['secure'=>'ssl','port'=>$p['port'] ?? 465];
        if (!empty($CFG['smtp_fallback'])) { $v[] = ['secure'=>'tls','port'=>587]; $v[] = ['secure'=>'none','port'=>25]; }
      } else { // none
        $v[] = ['secure'=>'none','port'=>$p['port'] ?? 25];
        if (!empty($CFG['smtp_fallback'])) { $v[] = ['secure'=>'tls','port'=>587]; $v[] = ['secure'=>'ssl','port'=>465]; }
      }
      return $v;
    };

    for ($attempt = 0; $attempt <= $maxRetries && !$sent; $attempt++) {
      $variants = $buildVariants($smtpParams);
      foreach ($variants as $idx=>$var) {
        $tryParams = $smtpParams;
        $tryParams['secure'] = $var['secure'];
        $tryParams['port']   = $var['port'];
        try {
          $res = smtp_send($tryParams, $CFG['email'], (array)$CFG['email']['to'], $fromAddr, $replyTo ?: null, $subject, $body, $ref, $ip);
          if (!empty($res['ok'])) {
            $sent = true;
            log_event('smtp_sent', ['to'=>$CFG['email']['to'], 'attempt'=>$attempt, 'variant'=>$var]);
            break;
          }
          $lastErr = $res['error'] ?? 'unknown';
          $transient = is_transient_smtp_error($lastErr) || stripos((string)$lastErr,'starttls failed') !== false || stripos((string)$lastErr,'connect') !== false;
          if (!$transient) { break; }
          log_event('smtp_fallback', ['error'=>$lastErr, 'next_variant'=>($variants[$idx+1] ?? null)]);
        } catch (Throwable $e) {
          $lastErr = $e->getMessage();
          log_event('smtp_fallback', ['error'=>$lastErr, 'next_variant'=>($variants[$idx+1] ?? null)]);
        }
      }

      if (!$sent && $attempt < $maxRetries && is_transient_smtp_error($lastErr)) {
        $sleepMs = (int)$CFG['smtp_retry_sleep_ms'] * ($attempt + 1);
        log_event('smtp_retry', ['attempt'=>$attempt+1, 'sleep_ms'=>$sleepMs, 'error'=>$lastErr]);
        usleep($sleepMs * 1000);
      } else {
        break;
      }
    }

    if (!$sent) { log_event('smtp_error', ['error'=>$lastErr]); }
  } else {
    log_event('smtp_error', ['error'=>'SMTP host not configured']);
  }
}

// AUTO-REPLY (optional courtesy message to submitter)
try {
  $ar = (array)($CFG['auto_reply'] ?? []);
  if (!empty($ar['enabled']) && !empty($email) && filter_var($email, FILTER_VALIDATE_EMAIL)) {
    if (!empty($CFG['smtp']['host'])) {
      $fromAck = sanitize_header((string)($ar['from'] ?? $CFG['smtp']['user']));
      $subAck  = sanitize_header((string)($ar['subject'] ?? 'Thanks — we received your message'));
      $bodyAck = "Thanks for reaching out.\n\nRef: $ref\n\nWe have received your message and will get back to you soon.";
      $resAck = smtp_send($CFG['smtp'], $CFG['email'], [$email], $fromAck, null, $subAck, $bodyAck, $ref, $ip);
      log_event('auto_reply', ['ok'=>!empty($resAck['ok']), 'to'=>$email, 'error'=>$resAck['error'] ?? null]);
    } else {
      log_event('auto_reply_skip', ['reason'=>'smtp_not_configured']);
    }
  }
} catch (Throwable $e) { log_event('auto_reply_error', ['error'=>$e->getMessage()]); }

// N8N FORWARD (if enabled and URL present)
if ($targets['n8n'] && !empty($CFG['json_forward_url']) && function_exists('curl_init')) {
  $json = json_encode($clean + ['_ref'=>$ref], JSON_UNESCAPED_UNICODE);
  $sig  = hash_hmac('sha256', $json, (string)$CFG['json_forward_secret']);

  $maxFR = max(0, (int)$CFG['forward_retries']);
  $okFwd = false; $lastErrF = null; $codeF = 0;

  for ($fa=0; $fa <= $maxFR; $fa++) {
    $ch = curl_init($CFG['json_forward_url']);
    curl_setopt_array($ch, [
      CURLOPT_POST => true,
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_HTTPHEADER => ['Content-Type: application/json','Accept: application/json','X-Signature: '.$sig],
      CURLOPT_POSTFIELDS => $json,
      CURLOPT_TIMEOUT => (int)$CFG['forward_timeout'],
      CURLOPT_CONNECTTIMEOUT => (int)$CFG['forward_connect'],
    ]);
    $resp = curl_exec($ch);
    $err  = curl_error($ch);
    $info = curl_getinfo($ch);
    $codeF = (int)($info['http_code'] ?? 0);
    curl_close($ch);

    $transient = (!empty($err) || ($codeF >= 500 && $codeF < 600) || $codeF === 0);
    if (!$transient && $codeF >= 200 && $codeF < 300) { $okFwd = true; break; }

    if ($fa < $maxFR && $transient) {
      $sleepMs = (int)$CFG['forward_retry_sleep_ms'] * ($fa + 1);
      log_event('forward_retry', ['attempt'=>$fa+1,'sleep_ms'=>$sleepMs,'http_code'=>$codeF,'err'=>$err ?: null]);
      usleep($sleepMs * 1000);
    } else {
      $lastErrF = $err ?: ('http '.$codeF);
      break;
    }
  }

  log_event('n8n_forward', ['ok'=>$okFwd,'http_code'=>$codeF,'err'=>$lastErrF]);

  if (!$okFwd && !empty($CFG['forward_queue_enabled']) && !empty($CFG['forward_queue_on_fail'])) {
    try {
      $db->exec("CREATE TABLE IF NOT EXISTS forwards (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at INTEGER, ref TEXT, json TEXT, attempts INTEGER, last_error TEXT)");
      $ins = $db->prepare("INSERT INTO forwards(created_at, ref, json, attempts, last_error) VALUES(?,?,?,?,?)");
      $ins->execute([time(), $ref, $json, ($maxFR+1), (string)$lastErrF]);
      log_event('forward_queued', ['ref'=>$ref]);
    } catch (Throwable $e) {
      log_event('forward_queue_error', ['error'=>$e->getMessage()]);
    }
  }
}
elseif ($targets['n8n'] && !empty($CFG['json_forward_url']) && !function_exists('curl_init')) {
  log_event('n8n_forward_skip', ['reason'=>'curl_missing']);
}

// Final response (if not already sent in async mode)
if (!isset($__responded) || $__responded === false) {
  log_event('responded', ['ref'=>$ref]);
  if (!headers_sent()) {
    if (isset($__rate_remaining)) header('X-RateLimit-Remaining: ' . (string)$__rate_remaining);
    header('X-Submission-Ref: ' . $ref);
  }
  header('X-Duplicate: 0');
  echo json_encode(['ok'=>true,'ref'=>$ref]);
}
