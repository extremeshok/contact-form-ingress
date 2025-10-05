<?php
declare(strict_types=1);

$serverMeta = getenv('INGRESS_TEST_SERVER');
if ($serverMeta !== false && $serverMeta !== '') {
    $decoded = json_decode($serverMeta, true);
    if (is_array($decoded)) {
        foreach ($decoded as $key => $value) {
            $_SERVER[$key] = $value;
        }
    }
}

$getMeta = getenv('INGRESS_TEST_GET');
if ($getMeta !== false && $getMeta !== '') {
    $decoded = json_decode($getMeta, true);
    if (is_array($decoded)) {
        $_GET = $decoded;
        if (!isset($_SERVER['QUERY_STRING'])) {
            $_SERVER['QUERY_STRING'] = http_build_query($decoded, '', '&');
        }
    }
}

$postMeta = getenv('INGRESS_TEST_POST');
if ($postMeta !== false && $postMeta !== '') {
    $decoded = json_decode($postMeta, true);
    if (is_array($decoded)) {
        $_POST = $decoded;
    }
}

$cookieMeta = getenv('INGRESS_TEST_COOKIE');
if ($cookieMeta !== false && $cookieMeta !== '') {
    $decoded = json_decode($cookieMeta, true);
    if (is_array($decoded)) {
        $_COOKIE = $decoded;
        if (!empty($decoded)) {
            $pairs = [];
            foreach ($decoded as $k => $v) {
                $pairs[] = $k . '=' . $v;
            }
            $_SERVER['HTTP_COOKIE'] = implode('; ', $pairs);
        }
    }
}

$bodyMeta = getenv('INGRESS_TEST_BODY');
if ($bodyMeta !== false && $bodyMeta !== '') {
    $_SERVER['INGRESS_TEST_BODY'] = $bodyMeta;
} else {
    unset($_SERVER['INGRESS_TEST_BODY']);
}

if (!isset($_SERVER['REQUEST_METHOD'])) {
    $_SERVER['REQUEST_METHOD'] = 'GET';
}

if (!isset($_GET) || !is_array($_GET)) {
    $_GET = [];
    if (!empty($_SERVER['QUERY_STRING'])) {
        parse_str($_SERVER['QUERY_STRING'], $_GET);
    }
}

if (!isset($_POST) || !is_array($_POST)) {
    $_POST = [];
}

$_REQUEST = array_merge($_GET, $_POST);
