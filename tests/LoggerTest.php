<?php
namespace SimpleLog\Tests;

use Psr\Log\LogLevel;
use SimpleLog\Logger;
use SimpleLog\Tests\Fixture\StringableMessage;

/**
 * Unit tests for SimpleLog\Logger.
 */
final class LoggerTest extends \PHPUnit\Framework\TestCase
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
        $this->logFile = tempnam('/tmp', 'SimpleLogUnitTest');

        if (\file_exists($this->logFile)) {
            \unlink($this->logFile);
        }
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

    /**
     * @test Logger implements PSR-3 Psr\Log\LoggerInterface
     */
    public function testLoggerImplementsPRS3Interface()
    {
        $this->assertInstanceOf(\Psr\Log\LoggerInterface::class, $this->logger);
    }

    /**
     * @test   Constructor sets expected properties.
     * @throws \Exception
     */
    public function testConstructorSetsProperties()
    {
        // Given
        $logFileProperty  = new \ReflectionProperty(Logger::class, 'logFile');
        $channelProperty  = new \ReflectionProperty(Logger::class, 'channel');
        $stdoutProperty   = new \ReflectionProperty(Logger::class, 'stdout');
        $logLevelProperty = new \ReflectionProperty(Logger::class, 'logLevel');

        // And
        $logFileProperty->setAccessible(true);
        $channelProperty->setAccessible(true);
        $stdoutProperty->setAccessible(true);
        $logLevelProperty->setAccessible(true);

        // Then
        $this->assertEquals($this->logFile, $logFileProperty->getValue($this->logger));
        $this->assertEquals(self::TEST_CHANNEL, $channelProperty->getValue($this->logger));
        $this->assertFalse($stdoutProperty->getValue($this->logger));
        $this->assertEquals(Logger::LEVELS[LogLevel::DEBUG], $logLevelProperty->getValue($this->logger));
    }

    /**
     * @test         setLogLevel sets the correct log level.
     * @dataProvider dataProviderForSetLogLevel
     * @param string $logLevel
     * @param int    $expectedLogLevelCode
     * @throws       \Exception
     */
    public function testSetLogLevelUsingConstants(string $logLevel, int $expectedLogLevelCode)
    {
        // Given
        $this->logger->setLogLevel($logLevel);
        $logLevelProperty = new \ReflectionProperty(Logger::class, 'logLevel');
        $logLevelProperty->setAccessible(true);

        // When
        $logLevelCode = $logLevelProperty->getValue($this->logger);

        // Then
        $this->assertEquals($expectedLogLevelCode, $logLevelCode);
    }

    /**
     * @return array [log level, log level code]
     */
    public function dataProviderForSetLogLevel(): array
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

    /**
     * @test   setLogLevel throws a \DomainException when set to an invalid log level.
     * @throws \Exception
     */
    public function testSetLogLevelWithBadLevelException()
    {
        // Then
        $this->expectException(\DomainException::class);

        // When
        $this->logger->setLogLevel('ThisLogLevelDoesNotExist');
    }


    /**
     * @test         setChannel sets the channel property.
     * @dataProvider dataProviderForSetChannel
     * @param        string $channel
     * @throws       \Exception
     */
    public function testSetChannel(string $channel)
    {
        // Given
        $channelProperty = new \ReflectionProperty(Logger::class, 'channel');
        $channelProperty->setAccessible(true);

        // When
        $this->logger->setChannel($channel);

        // Then
        $this->assertEquals($channel, $channelProperty->getValue($this->logger));
    }

    /**
     * @return array [channel]
     */
    public function dataProviderForSetChannel(): array
    {
        return [
            ['newchannel'],
            ['evennewerchannel'],
        ];
    }

    /**
     * @test         setOutput sets the stdout property.
     * @dataProvider dataProviderForSetOutput
     * @param        bool $output
     * @throws       \Exception
     */
    public function testSetOutput(bool $output)
    {
        // Given
        $stdout_property = new \ReflectionProperty(Logger::class, 'stdout');
        $stdout_property->setAccessible(true);

        // When
        $this->logger->setOutput($output);

        // Then
        $this->assertEquals($output, $stdout_property->getValue($this->logger));
    }

    /**
     * @return array [output]
     */
    public function dataProviderForSetOutput(): array
    {
        return [
            [true],
            [false],
        ];
    }

    /**
     * @test         Logger creates properly formatted log lines with the right log level for a string.
     * @dataProvider dataProviderForLogging
     * @param string $logLevel
     */
    public function testLoggingWithString(string $logLevel)
    {
        // When
        $this->logger->$logLevel(self::TEST_MESSAGE);
        $logLine = \trim(\file_get_contents($this->logFile));

        // Then
        $this->assertTrue((bool) preg_match(self::TEST_LOG_REGEX, $logLine));
        $this->assertTrue((bool) preg_match("/\[$logLevel\]/", $logLine));
    }

    /**
     * @test         Logger creates properly formatted log lines with the right log level for a Stringable.
     * @dataProvider dataProviderForLogging
     * @param string $logLevel
     */
    public function testLoggingWithStringable(string $logLevel)
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
     * @return array [loglevel]
     */
    public function dataProviderForLogging(): array
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

    /**
     * @test Data context array shows up as a JSON string.
     */
    public function testDataContext()
    {
        // When
        $this->logger->info(self::TEST_MESSAGE, ['key1' => 'value1', 'key2' => 6]);
        $logLine = \trim(\file_get_contents($this->logFile));

        // Then
        $this->assertTrue((bool) \preg_match('/\s{"key1":"value1","key2":6}\s/', $logLine));
    }

    /**
     * @test Logging an exception
     */
    public function testExceptionTextWhenLoggingErrorWithExceptionData()
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

    /**
     * @test Log lines will be on a single line even if there are newline characters in the log message.
     */
    public function testLogMessageIsOneLineEvenThoughItHasNewLineCharacters()
    {
        // When
        $this->logger->info("This message has a new line\nAnd another\n", ['key' => 'value']);

        // Then
        $logLines = \file($this->logFile);
        $this->assertEquals(1, \count($logLines));
    }

    /**
     * @test Log lines will be on a single line even if there are newline characters in the log message.
     */
    public function testLogMessageIsOneLineEvenThoughItHasNewLineCharactersInData()
    {
        // When
        $this->logger->info('Log message', ['key' => "Value\nwith\new\lines\n"]);

        // Then
        $logLines = \file($this->logFile);
        $this->assertEquals(1, \count($logLines));
    }

    /**
     * @test Log lines will be on a single line even if there are newline characters in the exception.
     */
    public function testLogMessageIsOneLineEvenThoughItHasNewLineCharactersInException()
    {
        // When
        $this->logger->info('Log message', ['key' => 'value', 'exception' => new \Exception("This\nhas\newlines\nin\nit")]);

        // Then
        $logLines = \file($this->logFile);
        $this->assertEquals(1, \count($logLines));
    }

    /**
     * @test Minimum log levels determine what log levels get logged.
     */
    public function testMinimumLogLevels()
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
        $this->assertEquals(4, \count($logLines));
    }

    /**
     * @test Minimum log levels determine what log levels get logged.
     */
    public function testMinimumLogLevelsByCheckingFileExistsBelowLogLevel()
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

    /**
     * @test Minimum log levels determine what log levels get logged.
     */
    public function testMinimumLogLevelsByCheckingFileExistsAboveLogLevel()
    {
        // Given
        $this->logger->setLogLevel(LogLevel::ERROR);

        // When
        $this->logger->error('This will be logged.');

        // Then
        $this->assertTrue(\file_exists($this->logFile));
    }

    /**
     * @test   Exception is thrown if the log file cannot be opened.
     * @throws \Exception
     */
    public function testLogExceptionCannotOpenFile()
    {
        // Given
        $badLogger = new Logger('/this/file/should/not/exist/on/any/system/if/it/does/well/oh/well/this/test/will/fail/logfile123.loglog.log', self::TEST_CHANNEL);

        // Then
        $this->expectException(\RuntimeException::class);

        // When
        $badLogger->info('This is not going to work, hence the test for the exception!');
    }

    /**
     * @test After setting output to true the logger will output log lines to STDOUT.
     */
    public function testLoggingToStdOut()
    {
        // Given
        $this->logger->setOutput(true);

        // Then
        $this->expectOutputRegex('/^\d{4}-\d{2}-\d{2} [ ] \d{2}:\d{2}:\d{2}[.]\d{6} \s \[\w+\] \s \[\w+\] \s \[pid:\d+\] \s Test Message \s {.*} \s {.*}/x');

        // When
        $this->logger->info('TestMessage');
    }
 
    /**
     * @test   Time should be in YYYY-MM-DD HH:mm:SS.uuuuuu format.
     * @throws \Exception
     */
    public function testGetTime()
    {
        // Given
        $reflection = new \ReflectionClass($this->logger);
        $method     = $reflection->getMethod('getTime');
        $method->setAccessible(true);

        // When
        $time = $method->invoke($this->logger);

        // Then
        $this->assertMatchesRegularExpression('/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}[.]\d{6}$/', $time);
    }
}
