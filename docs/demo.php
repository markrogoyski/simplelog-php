<?php
\file_exists('../tests/bootstrap.php') && require_once('../tests/bootstrap.php');
\file_exists('tests/bootstrap.php') && require_once('tests/bootstrap.php');

use SimpleLog\Logger;

// Log configuration
$logFile = '/dev/null';
$channel = 'demo';

// Create the logger
$logger = new Logger($logFile, $channel);

// Set optional output to screen
$logger->setOutput(true);

// Logging at different log levels without context.
$logger->debug('This is a debug message.');
$logger->info('This is an info message.');
$logger->notice('This is a notice message.');
$logger->warning('This is a warning message.');
$logger->error('This is an error message.');
$logger->critical('This is a critical message.');
$logger->alert('This is an alert message.');
$logger->emergency('This is an emergency message.');

// Logging with context
$logger->info('This is an info message with context.', ['method' => 'GET', 'endpoint' => '/v2/demo']);

// Logging with context that includes an exception.
$e = new \RuntimeException('KaPoW! Exception Message');
$logger->error('Something bad happened', ['exception' => $e, 'endpoint' => '/v2/demo']);
