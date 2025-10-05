<?php
declare(strict_types=1);

$storage = getenv('INGRESS_TEST_STORAGE') ?: sys_get_temp_dir() . '/ingress_test_default';
if (!is_dir($storage)) {
    @mkdir($storage, 0700, true);
}

$allowedOriginsRaw = getenv('INGRESS_TEST_ALLOWED_ORIGINS') ?: 'https://tests.extremeshok.com';
$allowedOrigins = array_values(array_filter(array_map('trim', explode(',', $allowedOriginsRaw))));
if (empty($allowedOrigins)) {
    $allowedOrigins = ['https://tests.extremeshok.com'];
}

$trustedProxiesRaw = getenv('INGRESS_TEST_TRUSTED_PROXIES') ?: '';
$trustedProxies = array_values(array_filter(array_map('trim', explode(',', $trustedProxiesRaw))));
$trustedHeadersRaw = getenv('INGRESS_TEST_TRUSTED_HEADERS') ?: 'x-forwarded-for,x-real-ip,forwarded';
$trustedHeaders = array_values(array_filter(array_map('trim', explode(',', $trustedHeadersRaw))));

return [
    'secret' => getenv('INGRESS_TEST_SECRET') ?: 'test-secret-3fb204c1e42847c4',
    'json_forward_secret' => getenv('INGRESS_TEST_JSON_FORWARD_SECRET') ?: 'forward-secret-6c650f086b03',
    'allowed_origins' => $allowedOrigins,
    'notify_targets' => getenv('INGRESS_TEST_NOTIFY_TARGETS') ?: '',
    'accept_payload' => getenv('INGRESS_TEST_ACCEPT_PAYLOAD') ?: 'both',
    'storage_dir' => $storage,
    'token_min_age' => (int)(getenv('INGRESS_TEST_TOKEN_MIN_AGE') ?: 0),
    'rate_limit' => [
        'window_sec' => (int)(getenv('INGRESS_TEST_RATE_WINDOW') ?: 300),
        'max_per_ip' => (int)(getenv('INGRESS_TEST_RATE_LIMIT') ?: 5),
    ],
    'dedupe_window_sec' => (int)(getenv('INGRESS_TEST_DEDUPE_WINDOW') ?: 3600),
    'async_notify' => '0',
    'smtp' => [
        'host' => getenv('INGRESS_TEST_SMTP_HOST') ?: 'smtp.test.local',
        'user' => getenv('INGRESS_TEST_SMTP_USER') ?: 'notify@test.local',
        'pass' => getenv('INGRESS_TEST_SMTP_PASS') ?: 'smtp-test-pass-1',
        'port' => (int)(getenv('INGRESS_TEST_SMTP_PORT') ?: 2525),
        'secure' => getenv('INGRESS_TEST_SMTP_SECURE') ?: 'none',
        'auth' => getenv('INGRESS_TEST_SMTP_AUTH') ?: 'none',
        'helo' => getenv('INGRESS_TEST_SMTP_HELO') ?: 'tests.extremeshok.com',
        'verify_peer' => false,
        'verify_peer_name' => false,
        'allow_self_signed' => true,
    ],
    'email' => [
        'to' => ['notify@test.local'],
        'subject_prefix' => 'Test :: ',
    ],
    'json_forward_url' => getenv('INGRESS_TEST_JSON_FORWARD_URL') ?: '',
    'min_name_chars' => 6,
    'min_message_chars' => 40,
    'proxy' => [
        'enabled' => (bool)(getenv('INGRESS_TEST_PROXY_ENABLED') ?: false),
        'trusted_proxies' => $trustedProxies,
        'trusted_headers' => $trustedHeaders,
        'max_chain' => (int)(getenv('INGRESS_TEST_PROXY_MAX_CHAIN') ?: 5),
    ],
    'extra_cmds' => [
        'enabled' => true,
        'health' => true,
        'check' => true,
        'version' => false,
        'probe_smtp' => false,
        'flush_queue' => false,
        'key' => '',
        'allow_ips' => [],
    ],
    'debug' => (bool)(getenv('INGRESS_TEST_DEBUG') ?: false),
];
