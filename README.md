![SimpleLog Logo](https://github.com/markrogoyski/simplelog-php/blob/master/docs/image/SimpleLogLogo.png?raw=true)

SimpleLog
=====================

### Powerful PSR-3 logging. So easy, it's simple!

SimpleLog is a powerful PSR-3 logger for PHP that is simple to use.

Simplicity is achieved by providing great defaults. No options to configure! Yet flexible enough to meet most logging needs.
And if your application's logging needs expand beyond what SimpleLog provides, since it implements PSR-3, you can drop in
another great PSR-3 logger like [MonoLog](https://github.com/Seldaek/monolog) in its place when the time comes with minimal changes.

[![Coverage Status](https://coveralls.io/repos/github/markrogoyski/simplelog-php/badge.svg?branch=master)](https://coveralls.io/github/markrogoyski/simplelog-php?branch=master)
[![License](https://poser.pugx.org/markrogoyski/simplelog-php/license)](https://packagist.org/packages/markrogoyski/simplelog-php)

Features
--------

 * Power and Simplicity
 * PSR-3 logger interface
 * Multiple log level severities
 * Log channels
 * Process ID logging
 * Custom log messages
 * Custom contextual data
 * Exception logging

Setup
-----

 Add the library to your `composer.json` file in your project:

```javascript
{
  "require": {
      "markrogoyski/simplelog-php": "2.*"
  }
}
```

Use [composer](http://getcomposer.org) to install the library:

```bash
$ php composer.phar install
```

Composer will install SimpleLog inside your vendor folder. Then you can add the following to your
.php files to use the library with Autoloading.

```php
require_once(__DIR__ . '/vendor/autoload.php');
```

Alternatively, use composer on the command line to require and install SimpleLog:

```
$ php composer.phar require markrogoyski/simplelog-php:2.*
```

### Minimum Requirements
 * PHP 8.0

- **Note**: For PHP 7.4, use v1.0 (`markrogoyski/simplelog-php:1.0`)
- **Note**: For PHP 7.0–7.3, use v0.4 (`markrogoyski/simplelog-php:0.4`)

Usage
-----

### Simple 20-Second Getting-Started Tutorial
```php
$logfile = '/path/to/logfile.log';
$channel = 'events';
$logger  = new SimpleLog\Logger($logfile, $channel);

$logger->info('SimpleLog really is simple.');
```

That's it! Your application is logging!

### Extended Example
```php
$logfile = '/var/log/events.log';
$channel = 'billing';
$logger  = new SimpleLog\Logger($logfile, $channel);

$logger->info('Begin process that usually fails.', ['process' => 'invoicing', 'user' => $user]);

try {
    invoiceUser($user); // This usually fails
} catch (\Exception $e) {
    $logger->error('Billing failure.', ['process' => 'invoicing', 'user' => $user, 'exception' => $e]);
}
```

Logger output
```
2017-02-13 00:35:55.426630  [info]  [billing] [pid:17415] Begin process that usually fails. {"process":"invoicing","user":"bob"}  {}
2017-02-13 00:35:55.430071  [error] [billing] [pid:17415] Billing failure.  {"process":"invoicing","user":"bob"}  {"message":"Could not process invoice.","code":0,"file":"/path/to/app.php","line":20,"trace":[{"file":"/path/to/app.php","line":13,"function":"invoiceUser","args":["mark"]}]}
```

### Log Output
Log lines have the following format:
```
YYYY-mm-dd HH:ii:ss.uuuuuu  [loglevel]  [channel]  [pid:##]  Log message content  {"Optional":"JSON Contextual Support Data"}  {"Optional":"Exception Data"}
```

Log lines are easily readable and parsable. Log lines are always on a single line. Fields are tab separated.

### Log Levels

SimpleLog has eight log level severities based on [PSR Log Levels](http://www.php-fig.org/psr/psr-3/#psrlogloglevel).

```php
$logger->debug('Detailed information about the application run.');
$logger->info('Informational messages about the application run.');
$logger->notice('Normal but significant events.');
$logger->warning('Information that something potentially bad has occured.');
$logger->error('Runtime error that should be monitored.');
$logger->critical('A service is unavailable or unresponsive.');
$logger->alert('The entire site is down.');
$logger->emergency('The Web site is on fire.');
```

By default all log levels are logged. The minimum log level can be changed in two ways:
 * Optional constructor parameter
 * Setter method at any time

```php
use Psr\Log\LogLevel;

// Optional constructor Parameter (Only error and above are logged [error, critical, alert, emergency])
$logger = new SimpleLog\Logger($logfile, $channel, LogLevel::ERROR);

// Setter method (Only warning and above are logged)
$logger->setLogLevel(LogLevel::WARNING);
```

### Contextual Data
SimpleLog enables logging best practices to have general-use log messages with contextual support data to give context to the message.

The second argument to a log message is an associative array of key-value pairs that will log as a JSON string, serving as the contextual support data to the log message.

```php
// Add context to a Web request.
$log->info('Web request initiated', ['method' => 'GET', 'endpoint' => 'user/account', 'queryParameters' => 'id=1234']);

// Add context to a disk space warning.
$log->warning('Free space is below safe threshold.', ['volume' => '/var/log', 'availablePercent' => 4]);
```

### Logging Exceptions
Exceptions are logged with the contextual data using the key *exception* and the value the exception variable.

```php
catch (\Exception $e) {
    $logger->error('Something exceptional has happened', ['exception' => $e]);
}
```

### Log Channels
Think of channels as namespaces for log lines. If you want to have multiple loggers or applications logging to a single log file, channels are your friend.

Channels can be set in two ways:
 * Constructor parameter
 * Setter method at any time

```php
// Constructor Parameter
$channel = 'router';
$logger  = new SimpleLog\Logger($logfile, $channel);

// Setter method
$logger->setChannel('database');
```

### Debug Features
#### Logging to STDOUT
When developing, you can turn on log output to the screen (STDOUT) as a convenience.

```php
$logger->setOutput(true);
$logger->debug('This will get logged to STDOUT as well as the log file.');
```

#### Dummy Logger
Suppose you need a logger to meet an injected dependency during a unit test, and you don't want it to actually log anything.
You can set the log level to ```Logger::LOG_LEVEL_NONE``` which won't log at any level.

```php
use SimpleLog\Logger;

$logger->setLogLevel(Logger::LOG_LEVEL_NONE);
$logger->info('This will not log to a file.');
```

Unit Tests
----------

```bash
$ cd tests
$ phpunit
```

[![Coverage Status](https://coveralls.io/repos/github/markrogoyski/simplelog-php/badge.svg?branch=master)](https://coveralls.io/github/markrogoyski/simplelog-php?branch=master)

Standards
---------

SimpleLog conforms to the following standards:

  * PSR-1  - Basic coding standard (http://www.php-fig.org/psr/psr-1/)
  * PSR-3 - Logger Interface (http://www.php-fig.org/psr/psr-3/)
  * PSR-4  - Autoloader (http://www.php-fig.org/psr/psr-4/)
  * PSR-12 - Extended coding style guide (http://www.php-fig.org/psr/psr-12/)

License
-------

SimpleLog is licensed under the MIT License.
