<?php

$host = isset($_SERVER['HTTP_HOST']) ? (string) $_SERVER['HTTP_HOST'] : '';
$forwardedHost = isset($_SERVER['HTTP_X_FORWARDED_HOST']) ? (string) $_SERVER['HTTP_X_FORWARDED_HOST'] : '';
$forwardedProto = isset($_SERVER['HTTP_X_FORWARDED_PROTO']) ? (string) $_SERVER['HTTP_X_FORWARDED_PROTO'] : '';

header('Content-Type: application/json');
http_response_code(200);
echo json_encode([
    'host' => $host,
    'x_forwarded_host' => $forwardedHost,
    'x_forwarded_proto' => $forwardedProto,
], JSON_UNESCAPED_SLASHES);
