<?php

namespace SimpleLog\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\LogLevel;
use SimpleLog\Logger;
use SimpleLog\Tests\Fixture\StringableMessage;

/**
 * Unit tests for SimpleLog\Logger.
 */
final class LoggerTest extends TestCase
{
    private string $logFile;

    private Logger $logger;

    private const TEST_CHANNEL      = 'unittest';
    private const TEST_MESSAGE      = 'Log message goes here.';

    private const TEST_LOG_REGEX    = "/^
        \d{4}-\d{2}-\d{2} [ ] \d{2}:\d{2}:\d{2}[.]\d{6}    # Timestamp (YYYY-mm-dd HH:ii:ss.uuuuuu)
        \s
        \[\w+\]                                            # [loglevel]
        \s
        \[unittest\]                                       # [channel]
        \s
        \[pid:\d+\]                                        # [pid:1234]
        \s
        Log [ ] message [ ] goes [ ] here.                 # Log message
        \s
        {.*}                                               # Data
        \s
        {.*}                                               # Exception data
    /x";

    /**
     * Set up test by instantiating a logger writing to a temporary file.
     */
    public function setUp(): void
    {
        $this->logFile = sys_get_temp_dir() . '/SimpleLogTest_' . uniqid();
        $this->logger = new Logger($this->logFile, self::TEST_CHANNEL);
    }

    /**
     * Clean up test by removing temporary log file.
     */
    public function tearDown(): void
    {
        if (file_exists($this->logFile)) {
            unlink($this->logFile);
        }
    }

    #[Test]
    public function loggerImplementsPRS3Interface(): void
    {
        $this->assertInstanceOf(\Psr\Log\LoggerInterface::class, $this->logger);
    }

    #[Test]
    public function constructorSetsProperties(): void
    {
        // When - log a message and verify constructor properties are reflected in output
        $this->logger->debug(self::TEST_MESSAGE);
        $logLine = \trim(\file_get_contents($this->logFile));

        // Then - channel is set correctly
        $this->assertStringContainsString('[' . self::TEST_CHANNEL . ']', $logLine);

        // And - log file is written to expected path
        $this->assertFileExists($this->logFile);

        // And - default log level is DEBUG (the lowest level logs)
        $this->assertTrue((bool) \preg_match('/\[debug\]/', $logLine));
    }

    #[Test]
    #[DataProvider('dataProviderForSetLogLevel')]
    public function setLogLevelUsingConstants(string $logLevel, int $expectedLogLevelCode): void
    {
        // Given
        $this->logger->setLogLevel($logLevel);
        $logLevelProperty = new \ReflectionProperty(Logger::class, 'logLevel');

        // When
        $logLevelCode = $logLevelProperty->getValue($this->logger);

        // Then
        $this->assertEquals($expectedLogLevelCode, $logLevelCode);
    }

    /**
     * @return array<array{string, int}>
     */
    public static function dataProviderForSetLogLevel(): array
    {
        return [
            [Logger::LOG_LEVEL_NONE, Logger::LEVELS[Logger::LOG_LEVEL_NONE]],
            [LogLevel::DEBUG,        Logger::LEVELS[LogLevel::DEBUG]],
            [LogLevel::INFO,         Logger::LEVELS[LogLevel::INFO]],
            [LogLevel::NOTICE,       Logger::LEVELS[LogLevel::NOTICE]],
            [LogLevel::WARNING,      Logger::LEVELS[LogLevel::WARNING]],
            [LogLevel::ERROR,        Logger::LEVELS[LogLevel::ERROR]],
            [LogLevel::CRITICAL,     Logger::LEVELS[LogLevel::CRITICAL]],
            [LogLevel::ALERT,        Logger::LEVELS[LogLevel::ALERT]],
            [LogLevel::EMERGENCY,    Logger::LEVELS[LogLevel::EMERGENCY]],
        ];
    }

    #[Test]
    public function setLogLevelWithBadLevelException(): void
    {
        // Then
        $this->expectException(\Psr\Log\InvalidArgumentException::class);

        // When
        $this->logger->setLogLevel('ThisLogLevelDoesNotExist');
    }

    #[Test]
    public function setChannel(): void
    {
        // Given
        $newChannel = 'newchannel';
        $this->logger->setChannel($newChannel);

        // When
        $this->logger->info(self::TEST_MESSAGE);
        $logLine = \trim(\file_get_contents($this->logFile));

        // Then
        $this->assertStringContainsString("[$newChannel]", $logLine);
    }

    #[Test]
    public function setStdoutFalseDoesNotPrintToStdout(): void
    {
        // Given
        $this->logger->setStdout(false);

        // When
        $this->logger->info(self::TEST_MESSAGE);

        // Then
        $this->expectOutputString('');
    }

    #[Test]
    #[DataProvider('dataProviderForLogging')]
    public function loggingWithString(string $logLevel): void
    {
        // When
        $this->logger->$logLevel(self::TEST_MESSAGE);
        $logLine = \trim(\file_get_contents($this->logFile));

        // Then
        $this->assertTrue((bool) preg_match(self::TEST_LOG_REGEX, $logLine));
        $this->assertTrue((bool) preg_match("/\[$logLevel\]/", $logLine));
    }

    #[Test]
    #[DataProvider('dataProviderForLogging')]
    public function loggingWithStringable(string $logLevel): void
    {
        // Given
        $message = new StringableMessage(self::TEST_MESSAGE);

        // When
        $this->logger->$logLevel($message);
        $logLine = \trim(\file_get_contents($this->logFile));

        // Then
        $this->assertTrue((bool) preg_match(self::TEST_LOG_REGEX, $logLine));
        $this->assertTrue((bool) preg_match("/\[$logLevel\]/", $logLine));
    }

    /**
     * @return array<array{string}>
     */
    public static function dataProviderForLogging(): array
    {
        return [
            ['debug'],
            ['info'],
            ['notice'],
            ['warning'],
            ['error'],
            ['critical'],
            ['alert'],
            ['emergency'],
        ];
    }

    #[Test]
    public function dataContext(): void
    {
        // When
        $this->logger->info(self::TEST_MESSAGE, ['key1' => 'value1', 'key2' => 6]);
        $logLine = \trim(\file_get_contents($this->logFile));

        // Then
        $this->assertTrue((bool) \preg_match('/\s{"key1":"value1","key2":6}\s/', $logLine));
    }

    #[Test]
    public function messageInterpolatesContextPlaceholders(): void
    {
        // When
        $this->logger->info('User {username} logged in', ['username' => 'mark']);
        $logLine = \trim(\file_get_contents($this->logFile));

        // Then - message has interpolated value
        $this->assertStringContainsString('User mark logged in', $logLine);

        // And - context still preserved in JSON data field
        $this->assertStringContainsString('"username":"mark"', $logLine);
    }

    #[Test]
    public function messageInterpolatesMultiplePlaceholders(): void
    {
        // When
        $this->logger->info('{user} performed {action} on {target}', ['user' => 'alice', 'action' => 'delete', 'target' => 'file.txt']);
        $logLine = \trim(\file_get_contents($this->logFile));

        // Then
        $this->assertStringContainsString('alice performed delete on file.txt', $logLine);
    }

    #[Test]
    public function messageWithPlaceholderNotInContextIsLeftAsIs(): void
    {
        // When
        $this->logger->info('User {username} has role {role}', ['username' => 'mark']);
        $logLine = \trim(\file_get_contents($this->logFile));

        // Then - existing placeholder replaced, missing one left intact
        $this->assertStringContainsString('User mark has role {role}', $logLine);
    }

    #[Test]
    public function messageInterpolationSkipsArrayValues(): void
    {
        // When
        $this->logger->info('Data: {items}', ['items' => ['a', 'b', 'c']]);
        $logLine = \trim(\file_get_contents($this->logFile));

        // Then - array placeholder not interpolated
        $this->assertStringContainsString('Data: {items}', $logLine);
    }

    #[Test]
    public function messageInterpolationSkipsObjectsWithoutToString(): void
    {
        // When
        $this->logger->info('Object: {obj}', ['obj' => new \stdClass()]);
        $logLine = \trim(\file_get_contents($this->logFile));

        // Then
        $this->assertStringContainsString('Object: {obj}', $logLine);
    }

    #[Test]
    public function messageInterpolationUsesStringableObjects(): void
    {
        // Given
        $message = new StringableMessage('world');

        // When
        $this->logger->info('Hello {name}', ['name' => $message]);
        $logLine = \trim(\file_get_contents($this->logFile));

        // Then
        $this->assertStringContainsString('Hello world', $logLine);
    }

    #[Test]
    public function messageWithoutPlaceholdersIgnoresContext(): void
    {
        // When
        $this->logger->info('No placeholders here', ['key' => 'value']);
        $logLine = \trim(\file_get_contents($this->logFile));

        // Then - message unchanged, context still in JSON
        $this->assertStringContainsString('No placeholders here', $logLine);
        $this->assertStringContainsString('"key":"value"', $logLine);
    }

    #[Test]
    public function messageInterpolationWorksWithIntegerAndFloatValues(): void
    {
        // When
        $this->logger->info('Count: {count}, Rate: {rate}', ['count' => 42, 'rate' => 3.14]);
        $logLine = \trim(\file_get_contents($this->logFile));

        // Then
        $this->assertStringContainsString('Count: 42, Rate: 3.14', $logLine);
    }

    #[Test]
    public function exceptionTextWhenLoggingErrorWithExceptionData(): void
    {
        // Given
        $e = new \Exception('Exception123');

        // When
        $this->logger->error('Testing the Exception', ['exception' => $e]);
        $logLine = \trim(\file_get_contents($this->logFile));

        // Then
        $this->assertTrue((bool) \preg_match('/Testing the Exception/', $logLine));
        $this->assertTrue((bool) \preg_match('/Exception123/', $logLine));
        $this->assertTrue((bool) \preg_match('/code/', $logLine));
        $this->assertTrue((bool) \preg_match('/file/', $logLine));
        $this->assertTrue((bool) \preg_match('/line/', $logLine));
        $this->assertTrue((bool) \preg_match('/trace/', $logLine));
    }

    #[Test]
    public function logMessageIsOneLineEvenThoughItHasNewLineCharacters(): void
    {
        // When
        $this->logger->info("This message has a new line\nAnd another\n", ['key' => 'value']);

        // Then
        $logLines = \file($this->logFile);
        $this->assertCount(1, $logLines);
    }

    #[Test]
    public function logMessageIsOneLineEvenThoughItHasNewLineCharactersInData(): void
    {
        // When
        $this->logger->info('Log message', ['key' => "Value\nwith\new\lines\n"]);

        // Then
        $logLines = \file($this->logFile);
        $this->assertCount(1, $logLines);
    }

    #[Test]
    public function logMessageIsOneLineEvenThoughItHasNewLineCharactersInException(): void
    {
        // When
        $this->logger->info('Log message', ['key' => 'value', 'exception' => new \Exception("This\nhas\newlines\nin\nit")]);

        // Then
        $logLines = \file($this->logFile);
        $this->assertCount(1, $logLines);
    }

    #[Test]
    public function logLineHasExactlySevenTsvFields(): void
    {
        // When
        $this->logger->info('Simple message', ['key' => 'value']);
        $logLine = \trim(\file_get_contents($this->logFile));

        // Then - 7 fields means exactly 6 tab delimiters
        $this->assertSame(6, \substr_count($logLine, "\t"));
    }

    #[Test]
    public function tabsInMessageDoNotBreakTsvFields(): void
    {
        // When
        $this->logger->info("Message\twith\ttabs");
        $logLine = \trim(\file_get_contents($this->logFile));

        // Then - still exactly 6 tab delimiters
        $this->assertSame(6, \substr_count($logLine, "\t"));
        $this->assertStringNotContainsString("Message\twith", $logLine);
    }

    #[Test]
    public function tabsInContextDataDoNotBreakTsvFields(): void
    {
        // When
        $this->logger->info('Message', ['key' => "value\twith\ttabs"]);
        $logLine = \trim(\file_get_contents($this->logFile));

        // Then
        $this->assertSame(6, \substr_count($logLine, "\t"));
    }

    #[Test]
    public function tabsInChannelDoNotBreakTsvFields(): void
    {
        // Given
        $this->logger->setChannel("chan\tnel");

        // When
        $this->logger->info('Message');
        $logLine = \trim(\file_get_contents($this->logFile));

        // Then
        $this->assertSame(6, \substr_count($logLine, "\t"));
    }

    #[Test]
    public function tabsInExceptionDoNotBreakTsvFields(): void
    {
        // When
        $this->logger->info('Message', ['exception' => new \Exception("Error\twith\ttab")]);
        $logLine = \trim(\file_get_contents($this->logFile));

        // Then
        $this->assertSame(6, \substr_count($logLine, "\t"));
    }

    #[Test]
    public function carriageReturnsInMessageDoNotBreakLogLine(): void
    {
        // When
        $this->logger->info("Message\rwith\r\nreturns");
        $logLines = \file($this->logFile);

        // Then
        $this->assertCount(1, $logLines);
        $logLine = \trim($logLines[0]);
        $this->assertStringNotContainsString("\r", $logLine);
    }

    #[Test]
    public function carriageReturnsInContextDataDoNotBreakLogLine(): void
    {
        // When
        $this->logger->info('Message', ['key' => "value\rwith\r\nreturns"]);
        $logLines = \file($this->logFile);

        // Then
        $this->assertCount(1, $logLines);
        $logLine = \trim($logLines[0]);
        $this->assertStringNotContainsString("\r", $logLine);
    }

    #[Test]
    public function carriageReturnsInChannelDoNotBreakLogLine(): void
    {
        // Given
        $this->logger->setChannel("chan\r\nnel");

        // When
        $this->logger->info('Message');
        $logLines = \file($this->logFile);

        // Then
        $this->assertCount(1, $logLines);
        $logLine = \trim($logLines[0]);
        $this->assertStringNotContainsString("\r", $logLine);
    }

    #[Test]
    public function carriageReturnsInExceptionDoNotBreakLogLine(): void
    {
        // When
        $this->logger->info('Message', ['exception' => new \Exception("Error\rwith\r\nreturns")]);
        $logLines = \file($this->logFile);

        // Then
        $this->assertCount(1, $logLines);
        $logLine = \trim($logLines[0]);
        $this->assertStringNotContainsString("\r", $logLine);
    }

    #[Test]
    public function newlinesInChannelDoNotBreakLogLine(): void
    {
        // Given
        $this->logger->setChannel("chan\nnel");

        // When
        $this->logger->info('Message');
        $logLines = \file($this->logFile);

        // Then
        $this->assertCount(1, $logLines);
    }

    #[Test]
    public function minimumLogLevels(): void
    {
        // When
        $this->logger->setLogLevel(LogLevel::ERROR);

        // When
        $this->logger->debug('This will not be logged.');
        $this->logger->info('This will not be logged.');
        $this->logger->notice('This will not be logged.');
        $this->logger->warning('This will not be logged.');

        // And
        $this->logger->error('This will be logged.');
        $this->logger->critical('This will be logged.');
        $this->logger->alert('This will be logged.');
        $this->logger->emergency('This will be logged.');

        // Then
        $logLines = \file($this->logFile);
        $this->assertCount(4, $logLines);
    }

    #[Test]
    public function minimumLogLevelsByCheckingFileExistsBelowLogLevel(): void
    {
        // Given
        $this->logger->setLogLevel(LogLevel::ERROR);

        // When
        $this->logger->debug('This will not be logged.');
        $this->logger->info('This will not be logged.');
        $this->logger->notice('This will not be logged.');
        $this->logger->warning('This will not be logged.');

        // Then
        $this->assertFalse(\file_exists($this->logFile));

        $this->logger->error('This will be logged.');
        $this->assertTrue(\file_exists($this->logFile));
    }

    #[Test]
    public function logLevelNoneDisablesAllLogging(): void
    {
        // Given
        $this->logger->setLogLevel(Logger::LOG_LEVEL_NONE);

        // When
        $this->logger->debug('This will not be logged.');
        $this->logger->info('This will not be logged.');
        $this->logger->notice('This will not be logged.');
        $this->logger->warning('This will not be logged.');
        $this->logger->error('This will not be logged.');
        $this->logger->critical('This will not be logged.');
        $this->logger->alert('This will not be logged.');
        $this->logger->emergency('This will not be logged.');

        // Then
        $this->assertFalse(\file_exists($this->logFile));
    }

    #[Test]
    public function minimumLogLevelsByCheckingFileExistsAboveLogLevel(): void
    {
        // Given
        $this->logger->setLogLevel(LogLevel::ERROR);

        // When
        $this->logger->error('This will be logged.');

        // Then
        $this->assertTrue(\file_exists($this->logFile));
    }

    #[Test]
    public function logDirectlyRespectsMinimumLogLevel(): void
    {
        // Given
        $this->logger->setLogLevel(LogLevel::ERROR);

        // When
        $this->logger->log(LogLevel::DEBUG, 'This should not be logged.');
        $this->logger->log(LogLevel::INFO, 'This should not be logged.');
        $this->logger->log(LogLevel::WARNING, 'This should not be logged.');
        $this->logger->log(LogLevel::ERROR, 'This should be logged.');
        $this->logger->log(LogLevel::CRITICAL, 'This should be logged.');

        // Then
        $logLines = \file($this->logFile);
        $this->assertCount(2, $logLines);
    }

    #[Test]
    public function logWithInvalidLevelStringThrowsInvalidArgumentException(): void
    {
        // Then
        $this->expectException(\Psr\Log\InvalidArgumentException::class);

        // When
        $this->logger->log('banana', 'This should throw.');
    }

    #[Test]
    public function logWithIntegerLevelThrowsInvalidArgumentException(): void
    {
        // Then
        $this->expectException(\Psr\Log\InvalidArgumentException::class);

        // When
        $this->logger->log(42, 'This should throw.');
    }

    #[Test]
    public function logWithArrayLevelThrowsInvalidArgumentException(): void
    {
        // Then
        $this->expectException(\Psr\Log\InvalidArgumentException::class);

        // When
        $this->logger->log(['error'], 'This should throw.');
    }

    #[Test]
    public function logWithObjectLevelThrowsInvalidArgumentException(): void
    {
        // Then
        $this->expectException(\Psr\Log\InvalidArgumentException::class);

        // When
        $this->logger->log(new \stdClass(), 'This should throw.');
    }

    #[Test]
    public function logWithNullLevelThrowsInvalidArgumentException(): void
    {
        // Then
        $this->expectException(\Psr\Log\InvalidArgumentException::class);

        // When
        $this->logger->log(null, 'This should throw.');
    }

    #[Test]
    public function logWithBoolLevelThrowsInvalidArgumentException(): void
    {
        // Then
        $this->expectException(\Psr\Log\InvalidArgumentException::class);

        // When
        $this->logger->log(true, 'This should throw.');
    }

    #[Test]
    public function constructorThrowsExceptionForEmptyLogFilePath(): void
    {
        // Then
        $this->expectException(\InvalidArgumentException::class);

        // When
        new Logger('', self::TEST_CHANNEL);
    }

    #[Test]
    public function constructorThrowsExceptionWhenDirectoryDoesNotExist(): void
    {
        // Then
        $this->expectException(\InvalidArgumentException::class);

        // When
        new Logger('/nonexistent/directory/logfile.log', self::TEST_CHANNEL);
    }

    #[Test]
    public function logExceptionCannotOpenFile(): void
    {
        // Given - use a read-only directory so the file cannot be created
        $readOnlyDir = \sys_get_temp_dir() . '/simplelog_readonly_test_' . \getmypid();
        \mkdir($readOnlyDir, 0555, true);
        $badLogger = new Logger($readOnlyDir . '/logfile.log', self::TEST_CHANNEL);

        // Then
        $this->expectException(\RuntimeException::class);

        try {
            // When
            $badLogger->info('This is not going to work, hence the test for the exception!');
        } finally {
            \rmdir($readOnlyDir);
        }
    }

    #[Test]
    public function loggingToStdOut(): void
    {
        // Given
        $this->logger->setStdout(true);

        // Then
        $this->expectOutputRegex('/^\d{4}-\d{2}-\d{2} [ ] \d{2}:\d{2}:\d{2}[.]\d{6} \s \[\w+\] \s \[\w+\] \s \[pid:\d+\] \s Test Message \s {.*} \s {.*}/x');

        // When
        $this->logger->info('TestMessage');
    }

    #[Test]
    public function contextWithResourcePreservesSerializableDataAndIndicatesError(): void
    {
        // Given - a resource handle that json_encode cannot serialize
        $resource = \fopen('php://memory', 'r');

        // When
        $this->logger->info(self::TEST_MESSAGE, ['valid' => 'data', 'handle' => $resource]);
        $logLine = \trim(\file_get_contents($this->logFile));
        \fclose($resource);

        // Then - serializable data is preserved
        $this->assertStringContainsString('"valid":"data"', $logLine);

        // And - an error indicator is present so the failure is not silent
        $this->assertStringContainsString('_json_encode_error', $logLine);
    }

    #[Test]
    public function contextWithCircularReferencePreservesSerializableDataAndIndicatesError(): void
    {
        // Given - circular reference that json_encode cannot serialize
        $a = new \stdClass();
        $b = new \stdClass();
        $a->child = $b;
        $b->parent = $a;

        // When
        $this->logger->info(self::TEST_MESSAGE, ['valid' => 'data', 'circular' => $a]);
        $logLine = \trim(\file_get_contents($this->logFile));

        // Then - serializable data is preserved
        $this->assertStringContainsString('"valid":"data"', $logLine);

        // And - an error indicator is present
        $this->assertStringContainsString('_json_encode_error', $logLine);
    }

    #[Test]
    public function contextWithOnlySerializableDataHasNoErrorIndicator(): void
    {
        // When
        $this->logger->info(self::TEST_MESSAGE, ['key' => 'value', 'num' => 42]);
        $logLine = \trim(\file_get_contents($this->logFile));

        // Then - data is encoded normally
        $this->assertStringContainsString('"key":"value"', $logLine);
        $this->assertStringContainsString('"num":42', $logLine);

        // And - no error indicator
        $this->assertStringNotContainsString('_json_encode_error', $logLine);
    }

    #[Test]
    public function exceptionFallbackWithDoubleQuoteInMessageProducesValidJson(): void
    {
        // Given - an exception whose message contains a double quote
        $e = new \Exception('Something "broke" here');

        // When - call buildExceptionData via reflection, simulating json_encode failure on full data
        $reflection = new \ReflectionClass($this->logger);
        $method     = $reflection->getMethod('buildExceptionData');

        // Temporarily override json_encode behavior by testing the fallback path directly:
        // We invoke buildExceptionData and verify the result is always valid JSON.
        $result = $method->invoke($this->logger, $e);

        // Then - result must be valid JSON regardless of whether primary or fallback path was taken
        $this->assertNotNull(\json_decode($result));
        $this->assertStringContainsString('Something \"broke\" here', $result);
    }

    #[Test]
    public function exceptionFallbackProducesValidJsonWhenJsonEncodeFails(): void
    {
        // Given - an exception with a resource in trace args that will cause json_encode to fail
        //         and a message containing double quotes to expose the injection bug
        $resource = \fopen('php://memory', 'r');
        try {
            // Call a function with a resource arg so it appears in the exception trace
            (function ($res) {
                throw new \Exception('She said "hello"');
            })($resource);
        } catch (\Exception $e) {
            // This exception's trace contains a resource, so json_encode will fail
        }
        \fclose($resource);

        // When
        $this->logger->error('Exception test', ['exception' => $e]);
        $logLine = \trim(\file_get_contents($this->logFile));

        // Then - the log line should contain valid JSON for the exception field
        // Extract the last JSON object (exception data) from the TSV log line
        $fields = \explode("\t", $logLine);
        $exceptionJson = \end($fields);
        $decoded = \json_decode($exceptionJson, true);
        $this->assertNotNull($decoded, "Exception JSON is invalid: $exceptionJson");
        $this->assertSame('She said "hello"', $decoded['message']);
    }
}
