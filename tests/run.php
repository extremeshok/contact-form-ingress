<?php
declare(strict_types=1);

$root = dirname(__DIR__);
$phpBinary = PHP_BINARY;
$configPath = __DIR__ . '/config.test.php';
$preloadPath = __DIR__ . '/preload.php';

function run_request(array $options): array
{
    global $root, $phpBinary, $configPath, $preloadPath;

    $method = strtoupper($options['method'] ?? 'GET');
    $query = $options['query'] ?? [];
    $queryString = http_build_query($query, '', '&');
    $path = $options['path'] ?? '/ingress.php';
    $uri = $queryString === '' ? $path : $path . '?' . $queryString;

    $defaultServer = [
        'REQUEST_METHOD' => $method,
        'QUERY_STRING' => $queryString,
        'REQUEST_URI' => $uri,
        'SCRIPT_NAME' => $path,
        'SCRIPT_FILENAME' => $root . '/ingress.php',
        'DOCUMENT_ROOT' => $root,
        'SERVER_NAME' => 'tests.extremeshok.com',
        'HTTP_HOST' => 'tests.extremeshok.com',
        'SERVER_PORT' => '443',
        'HTTPS' => 'on',
        'SERVER_PROTOCOL' => 'HTTP/1.1',
        'REMOTE_ADDR' => '203.0.113.1',
        'HTTP_USER_AGENT' => 'IngressSelfTest/1.0',
        'HTTP_ACCEPT' => 'application/json',
        'HTTP_ORIGIN' => 'https://tests.extremeshok.com',
        'HTTP_REFERER' => 'https://tests.extremeshok.com/form',
    ];

    $server = array_merge($defaultServer, $options['server'] ?? []);

    $body = '';
    if (array_key_exists('json', $options)) {
        $body = json_encode($options['json'], JSON_UNESCAPED_SLASHES);
        if ($body === false) {
            throw new RuntimeException('Failed to encode JSON body');
        }
        $server['CONTENT_TYPE'] = $server['CONTENT_TYPE'] ?? 'application/json';
    } elseif (array_key_exists('body', $options)) {
        $body = (string)$options['body'];
    }

    if (!empty($options['content_type'])) {
        $server['CONTENT_TYPE'] = $options['content_type'];
    }

    if ($body !== '') {
        $server['CONTENT_LENGTH'] = (string)strlen($body);
    }

    $env = $_ENV;
    $env['CONFIG_PATH'] = $configPath;
    $env['INGRESS_TEST_SERVER'] = json_encode($server, JSON_UNESCAPED_SLASHES);
    if (!empty($query)) {
        $env['INGRESS_TEST_GET'] = json_encode($query, JSON_UNESCAPED_SLASHES);
    } else {
        unset($env['INGRESS_TEST_GET']);
    }
    if (!empty($options['json'])) {
        $env['INGRESS_TEST_BODY'] = $body;
    } else {
        unset($env['INGRESS_TEST_BODY']);
    }
    if (!empty($options['post'])) {
        $env['INGRESS_TEST_POST'] = json_encode($options['post'], JSON_UNESCAPED_SLASHES);
    } else {
        unset($env['INGRESS_TEST_POST']);
    }
    if (!empty($options['cookies'])) {
        $env['INGRESS_TEST_COOKIE'] = json_encode($options['cookies'], JSON_UNESCAPED_SLASHES);
    } else {
        unset($env['INGRESS_TEST_COOKIE']);
    }
    if (!empty($options['env'])) {
        foreach ($options['env'] as $key => $value) {
            if ($value === null) {
                unset($env[$key]);
            } else {
                $env[$key] = (string)$value;
            }
        }
    }

    $descriptors = [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];

    $command = escapeshellarg($phpBinary)
        . ' -d auto_prepend_file=' . escapeshellarg($preloadPath)
        . ' ' . escapeshellarg($root . '/ingress.php');

    $process = proc_open($command, $descriptors, $pipes, $root, $env);
    if (!is_resource($process)) {
        throw new RuntimeException('Failed to start PHP process');
    }

    if ($body !== '') {
        fwrite($pipes[0], $body);
    }
    fclose($pipes[0]);

    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);

    $exitCode = proc_close($process);

    return [
        'stdout' => $stdout,
        'stderr' => $stderr,
        'exit_code' => $exitCode,
    ];
}

function decode_response(string $json): array
{
    $decoded = json_decode($json, true);
    if (!is_array($decoded)) {
        throw new RuntimeException('Expected JSON response, got: ' . $json);
    }
    return $decoded;
}

function assert_true(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

function assert_equals($expected, $actual, string $message): void
{
    if ($expected !== $actual) {
        throw new RuntimeException($message . ' (expected ' . var_export($expected, true) . ', got ' . var_export($actual, true) . ')');
    }
}

$baseStorage = sys_get_temp_dir() . '/ingress_selftest_' . bin2hex(random_bytes(4));
@mkdir($baseStorage, 0700, true);

try {
    // 1. Placeholder secret should trigger configuration failure on non-diagnostic requests.
    $placeholderEnv = [
        'INGRESS_TEST_STORAGE' => $baseStorage . '/placeholder',
        'INGRESS_TEST_SECRET' => 'CHANGE_ME_LONG_RANDOM',
        'INGRESS_TEST_NOTIFY_TARGETS' => '',
        'INGRESS_TEST_PROXY_ENABLED' => '',
    ];
    $resp = run_request([
        'method' => 'GET',
        'query' => ['cmd' => 'token'],
        'server' => ['REMOTE_ADDR' => '198.51.100.5'],
        'env' => $placeholderEnv,
    ]);
    $payload = decode_response($resp['stdout']);
    assert_equals(false, $payload['ok'] ?? null, 'Placeholder secret should fail bootstrap');
    $issues = $payload['issues'] ?? [];
    assert_true(is_array($issues) && in_array('secret must be replaced with a long random string', $issues, true), 'Placeholder secret issue missing');

    // 2. Health endpoint should surface fatal issue but still respond.
    $resp = run_request([
        'method' => 'GET',
        'query' => ['cmd' => 'health'],
        'server' => ['REMOTE_ADDR' => '198.51.100.5'],
        'env' => $placeholderEnv,
    ]);
    $payload = decode_response($resp['stdout']);
    assert_equals(false, $payload['ok'] ?? null, 'Health should mark config not ok');
    assert_equals(false, $payload['config_ok'] ?? null, 'Health should report config_ok=false');
    assert_true(in_array('secret must be replaced with a long random string', $payload['config_issues']['fatal'] ?? [], true), 'Health fatal issues missing');

    // 3. JSON forward secret must not be left empty.
    $jsonSecretEnv = [
        'INGRESS_TEST_STORAGE' => $baseStorage . '/jsonsecret',
        'INGRESS_TEST_SECRET' => 'nonplaceholder-secret-123456789',
        'INGRESS_TEST_JSON_FORWARD_SECRET' => 'CHANGE_ME_json_forward_secret',
        'INGRESS_TEST_NOTIFY_TARGETS' => '',
        'INGRESS_TEST_PROXY_ENABLED' => '',
    ];
    $resp = run_request([
        'method' => 'GET',
        'query' => ['cmd' => 'token'],
        'server' => ['REMOTE_ADDR' => '198.51.100.6'],
        'env' => $jsonSecretEnv,
    ]);
    $payload = decode_response($resp['stdout']);
    assert_equals(false, $payload['ok'] ?? null, 'Empty json_forward_secret should fail bootstrap');
    assert_true(in_array('json_forward_secret must be configured with a non-empty secret', $payload['issues'] ?? [], true), 'json_forward_secret issue missing');

    // Prepare base env for functional tests.
    $happyStorage = $baseStorage . '/happy';
    @mkdir($happyStorage, 0700, true);
    $commonEnv = [
        'INGRESS_TEST_STORAGE' => $happyStorage,
        'INGRESS_TEST_SECRET' => 'super-secret-' . bin2hex(random_bytes(6)),
        'INGRESS_TEST_NOTIFY_TARGETS' => '',
        'INGRESS_TEST_PROXY_ENABLED' => '1',
        'INGRESS_TEST_TRUSTED_PROXIES' => '10.0.0.0/8,127.0.0.1',
        'INGRESS_TEST_TRUSTED_HEADERS' => 'x-forwarded-for,x-real-ip',
        'INGRESS_TEST_DEDUPE_WINDOW' => 3600,
        'INGRESS_TEST_RATE_LIMIT' => 5,
        'INGRESS_TEST_RATE_WINDOW' => 300,
    ];

    // 4. Token minting.
    $tokenResp = run_request([
        'method' => 'GET',
        'query' => ['cmd' => 'token'],
        'server' => [
            'REMOTE_ADDR' => '10.0.0.5',
            'HTTP_X_FORWARDED_FOR' => '203.0.113.10, 10.0.0.5',
            'HTTP_X_REAL_IP' => '203.0.113.10',
        ],
        'env' => $commonEnv,
    ]);
    $tokenPayload = decode_response($tokenResp['stdout']);
    assert_equals(true, $tokenPayload['ok'] ?? null, 'Token request should succeed');
    $token = $tokenPayload['token'] ?? '';
    assert_true(is_string($token) && $token !== '', 'Token missing in response');

    $message = str_repeat('Full happy path message. ', 2); // 46 chars
    $submissionBase = [
        'token' => $token,
        'name' => 'Marcus Aurelius',
        'email' => 'marcus@example.com',
        'phone' => '+12025550123',
        'message' => $message,
        'consent' => 'true',
        'dwell_ms' => '2000',
    ];

    // 5. Happy path submission.
    $submitResp = run_request([
        'method' => 'POST',
        'post' => $submissionBase,
        'content_type' => 'application/x-www-form-urlencoded',
        'cookies' => ['form_token' => $token],
        'server' => [
            'REMOTE_ADDR' => '10.0.0.5',
            'HTTP_X_FORWARDED_FOR' => '203.0.113.10, 10.0.0.5',
            'HTTP_X_REAL_IP' => '203.0.113.10',
        ],
        'env' => $commonEnv,
    ]);
    $submitPayload = decode_response($submitResp['stdout']);
    assert_equals(true, $submitPayload['ok'] ?? null, 'Submission should succeed');
    $ref = $submitPayload['ref'] ?? '';
    assert_true(is_string($ref) && $ref !== '', 'Submission ref missing');
    assert_true(empty($submitPayload['duplicate'] ?? false), 'First submission should not be duplicate');

    // Verify stored IP equals client IP from forwarded header.
    $dbNamePath = $happyStorage . DIRECTORY_SEPARATOR . '.db_name';
    assert_true(is_file($dbNamePath), 'Database name file missing');
    $dbName = trim((string)file_get_contents($dbNamePath));
    $pdo = new PDO('sqlite:' . $happyStorage . DIRECTORY_SEPARATOR . $dbName);
    $ipRow = $pdo->query('SELECT ip FROM submissions ORDER BY id DESC LIMIT 1')->fetch(PDO::FETCH_ASSOC);
    assert_equals('203.0.113.10', $ipRow['ip'] ?? null, 'Client IP should be resolved from proxy headers');

    // 6. Duplicate submission should short-circuit with duplicate flag.
    $dupResp = run_request([
        'method' => 'POST',
        'post' => $submissionBase,
        'content_type' => 'application/x-www-form-urlencoded',
        'cookies' => ['form_token' => $token],
        'server' => [
            'REMOTE_ADDR' => '10.0.0.5',
            'HTTP_X_FORWARDED_FOR' => '203.0.113.10, 10.0.0.5',
            'HTTP_X_REAL_IP' => '203.0.113.10',
        ],
        'env' => $commonEnv,
    ]);
    $dupPayload = decode_response($dupResp['stdout']);
    assert_equals(true, $dupPayload['ok'] ?? null, 'Duplicate response should still be ok');
    assert_equals(true, $dupPayload['duplicate'] ?? null, 'Duplicate flag missing');
    assert_equals($ref, $dupPayload['ref'] ?? null, 'Duplicate should reuse original ref');

    // 7. JSON submission path (accept_payload=json).
    $jsonStorage = $baseStorage . '/json';
    @mkdir($jsonStorage, 0700, true);
    $jsonEnv = $commonEnv;
    $jsonEnv['INGRESS_TEST_STORAGE'] = $jsonStorage;
    $jsonEnv['INGRESS_TEST_SECRET'] = 'json-secret-' . bin2hex(random_bytes(6));
    $jsonEnv['INGRESS_TEST_ACCEPT_PAYLOAD'] = 'json';

    $jsonTokenResp = run_request([
        'method' => 'GET',
        'query' => ['cmd' => 'token'],
        'server' => [
            'REMOTE_ADDR' => '10.0.0.6',
            'HTTP_X_FORWARDED_FOR' => '198.51.100.25, 10.0.0.6',
            'HTTP_X_REAL_IP' => '198.51.100.25',
        ],
        'env' => $jsonEnv,
    ]);
    $jsonTokenPayload = decode_response($jsonTokenResp['stdout']);
    assert_equals(true, $jsonTokenPayload['ok'] ?? null, 'JSON-mode token request should succeed');
    $jsonToken = $jsonTokenPayload['token'] ?? '';
    assert_true(is_string($jsonToken) && $jsonToken !== '', 'JSON-mode token missing');

    $jsonSubmission = [
        'token' => $jsonToken,
        'name' => 'Julia JSON',
        'email' => 'julia@example.com',
        'phone' => '+12025550188',
        'message' => str_repeat('JSON submission body ', 2),
        'consent' => true,
        'dwell_ms' => 2300,
    ];
    $jsonSubmitResp = run_request([
        'method' => 'POST',
        'json' => $jsonSubmission,
        'cookies' => ['form_token' => $jsonToken],
        'server' => [
            'REMOTE_ADDR' => '10.0.0.6',
            'HTTP_X_FORWARDED_FOR' => '198.51.100.25, 10.0.0.6',
            'HTTP_X_REAL_IP' => '198.51.100.25',
        ],
        'env' => $jsonEnv,
    ]);
    $jsonSubmitPayload = decode_response($jsonSubmitResp['stdout']);
    assert_equals(true, $jsonSubmitPayload['ok'] ?? null, 'JSON submission should succeed');
    assert_true(!empty($jsonSubmitPayload['ref'] ?? ''), 'JSON submission ref missing');

    $jsonDbNamePath = $jsonStorage . DIRECTORY_SEPARATOR . '.db_name';
    assert_true(is_file($jsonDbNamePath), 'JSON DB name file missing');
    $jsonDbName = trim((string)file_get_contents($jsonDbNamePath));
    $jsonPdo = new PDO('sqlite:' . $jsonStorage . DIRECTORY_SEPARATOR . $jsonDbName);
    $jsonIpRow = $jsonPdo->query('SELECT ip FROM submissions ORDER BY id DESC LIMIT 1')->fetch(PDO::FETCH_ASSOC);
    assert_equals('198.51.100.25', $jsonIpRow['ip'] ?? null, 'JSON mode should honour forwarded client IP');

    // 8. Rate limit enforcement (new storage, dedupe disabled).
    $rateStorage = $baseStorage . '/rate';
    @mkdir($rateStorage, 0700, true);
    $rateEnv = $commonEnv;
    $rateEnv['INGRESS_TEST_STORAGE'] = $rateStorage;
    $rateEnv['INGRESS_TEST_DEDUPE_WINDOW'] = 0;
    $rateEnv['INGRESS_TEST_RATE_LIMIT'] = 2;
    $rateEnv['INGRESS_TEST_RATE_WINDOW'] = 300;

    $tokenResp = run_request([
        'method' => 'GET',
        'query' => ['cmd' => 'token'],
        'server' => [
            'REMOTE_ADDR' => '10.0.0.9',
            'HTTP_X_FORWARDED_FOR' => '203.0.113.55, 10.0.0.9',
            'HTTP_X_REAL_IP' => '203.0.113.55',
        ],
        'env' => $rateEnv,
    ]);
    $tokenPayload = decode_response($tokenResp['stdout']);
    $rateToken = $tokenPayload['token'] ?? '';
    assert_true(is_string($rateToken) && $rateToken !== '', 'Rate test token missing');

    for ($i = 0; $i < 2; $i++) {
        $body = $submissionBase;
        $body['message'] = 'Rate limit message #' . $i . ' ' . str_repeat('X', 40);
        $body['token'] = $rateToken;
        $rateSubmit = run_request([
            'method' => 'POST',
            'post' => $body,
            'content_type' => 'application/x-www-form-urlencoded',
            'cookies' => ['form_token' => $rateToken],
            'server' => [
                'REMOTE_ADDR' => '10.0.0.9',
                'HTTP_X_FORWARDED_FOR' => '203.0.113.55, 10.0.0.9',
                'HTTP_X_REAL_IP' => '203.0.113.55',
            ],
            'env' => $rateEnv,
        ]);
        $payloadLoop = decode_response($rateSubmit['stdout']);
        assert_equals(true, $payloadLoop['ok'] ?? null, 'Initial rate submissions should succeed');
    }

    $body = $submissionBase;
    $body['message'] = 'Rate limit trip ' . str_repeat('Y', 40);
    $body['token'] = $rateToken;
    $rateTrip = run_request([
        'method' => 'POST',
        'post' => $body,
        'content_type' => 'application/x-www-form-urlencoded',
        'cookies' => ['form_token' => $rateToken],
        'server' => [
            'REMOTE_ADDR' => '10.0.0.9',
            'HTTP_X_FORWARDED_FOR' => '203.0.113.55, 10.0.0.9',
            'HTTP_X_REAL_IP' => '203.0.113.55',
        ],
        'env' => $rateEnv,
    ]);
    $rateTripPayload = decode_response($rateTrip['stdout']);
    assert_equals(false, $rateTripPayload['ok'] ?? null, 'Rate limit should fail on third submission');
    assert_equals('Too many submissions', $rateTripPayload['error'] ?? null, 'Rate limit error message mismatch');

    echo "All ingress self-tests passed\n";
} catch (Throwable $e) {
    fwrite(STDERR, 'Self-test failure: ' . $e->getMessage() . "\n");
    exit(1);
}
