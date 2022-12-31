<?php
namespace SimpleLog\Tests;

use Psr\Log\LogLevel;
use SimpleLog\Logger;

/**
 * Unit tests for SimpleLog\Logger.
 */
class LoggerTest extends \PHPUnit\Framework\TestCase
{
    /** @var string */
    private $logfile;

    /** @var Logger */
    private $logger;

    const TEST_CHANNEL      = 'unittest';
    const TEST_MESSAGE      = 'Log message goes here.';

    const TEST_LOG_REGEX    = "/^
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
        $this->logfile = tempnam('/tmp', 'SimpleLogUnitTest');

        if (file_exists($this->logfile)) {
            unlink($this->logfile);
        }
        $this->logger = new Logger($this->logfile, self::TEST_CHANNEL);
    }

    /**
     * Clean up test by removing temporary log file.
     */
    public function tearDown(): void
    {
        if (file_exists($this->logfile)) {
            unlink($this->logfile);
        }
    }

    /**
     * @testCase Logger implements PSR-3 Psr\Log\LoggerInterface
     */
    public function testLoggerImplementsPRS3Interface()
    {
        $this->assertInstanceOf(\Psr\Log\LoggerInterface::class, $this->logger);
    }

    /**
     * @testCase Constructor sets expected properties.
     * @throws   \Exception
     */
    public function testConstructorSetsProperties()
    {
        // Given
        $log_file_property  = new \ReflectionProperty(Logger::class, 'log_file');
        $channel_property   = new \ReflectionProperty(Logger::class, 'channel');
        $stdout_property    = new \ReflectionProperty(Logger::class, 'stdout');
        $log_level_property = new \ReflectionProperty(Logger::class, 'log_level');

        // And
        $log_file_property->setAccessible(true);
        $channel_property->setAccessible(true);
        $stdout_property->setAccessible(true);
        $log_level_property->setAccessible(true);

        // Then
        $this->assertEquals($this->logfile, $log_file_property->getValue($this->logger));
        $this->assertEquals(self::TEST_CHANNEL, $channel_property->getValue($this->logger));
        $this->assertFalse($stdout_property->getValue($this->logger));
        $this->assertEquals(Logger::LEVELS[LogLevel::DEBUG], $log_level_property->getValue($this->logger));
    }

    /**
     * @testCase     setLogLevel sets the correct log level.
     * @dataProvider dataProviderForSetLogLevel
     * @param string $log_level
     * @param int    $expected_log_level_code
     * @throws       \Exception
     */
    public function testSetLogLevelUsingConstants(string $log_level, int $expected_log_level_code)
    {
        // Given
        $this->logger->setLogLevel($log_level);
        $log_level_property = new \ReflectionProperty(Logger::class, 'log_level');
        $log_level_property->setAccessible(true);

        // When
        $log_level_code = $log_level_property->getValue($this->logger);

        // Then
        $this->assertEquals($expected_log_level_code, $log_level_code);
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
     * @testCase setLogLevel throws a \DomainException when set to an invalid log level.
     * @throws   \Exception
     */
    public function testSetLogLevelWithBadLevelException()
    {
        // Then
        $this->expectException(\DomainException::class);

        // When
        $this->logger->setLogLevel('ThisLogLevelDoesNotExist');
    }


    /**
     * @testCase     setChannel sets the channel property.
     * @dataProvider dataProviderForSetChannel
     * @param        string $channel
     * @throws       \Exception
     */
    public function testSetChannel(string $channel)
    {
        // Given
        $channel_property = new \ReflectionProperty(Logger::class, 'channel');
        $channel_property->setAccessible(true);

        // When
        $this->logger->setChannel($channel);

        // Then
        $this->assertEquals($channel, $channel_property->getValue($this->logger));
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
     * @testCase     setOutput sets the stdout property.
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
     * @testCase     Logger creates properly formatted log lines with the right log level.
     * @dataProvider dataProviderForLogging
     * @param string $logLevel
     */
    public function testLogging(string $logLevel)
    {
        // When
        $this->logger->$logLevel(self::TEST_MESSAGE);
        $log_line = trim(file_get_contents($this->logfile));

        // Then
        $this->assertTrue((bool) preg_match(self::TEST_LOG_REGEX, $log_line));
        $this->assertTrue((bool) preg_match("/\[$logLevel\]/", $log_line));
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
     * @testCase Data context array shows up as a JSON string.
     */
    public function testDataContext()
    {
        // When
        $this->logger->info(self::TEST_MESSAGE, ['key1' => 'value1', 'key2' => 6]);
        $log_line = trim(file_get_contents($this->logfile));

        // Then
        $this->assertTrue((bool) preg_match('/\s{"key1":"value1","key2":6}\s/', $log_line));
    }

    /**
     * @testCase Logging an exception
     */
    public function testExceptionTextWhenLoggingErrorWithExceptionData()
    {
        // Given
        $e = new \Exception('Exception123');

        // When
        $this->logger->error('Testing the Exception', ['exception' => $e]);
        $log_line = trim(file_get_contents($this->logfile));

        // Then
        $this->assertTrue((bool) preg_match('/Testing the Exception/', $log_line));
        $this->assertTrue((bool) preg_match('/Exception123/', $log_line));
        $this->assertTrue((bool) preg_match('/code/', $log_line));
        $this->assertTrue((bool) preg_match('/file/', $log_line));
        $this->assertTrue((bool) preg_match('/line/', $log_line));
        $this->assertTrue((bool) preg_match('/trace/', $log_line));
    }

    /**
     * @testCase Log lines will be on a single line even if there are newline characters in the log message.
     */
    public function testLogMessageIsOneLineEvenThoughItHasNewLineCharacters()
    {
        // When
        $this->logger->info("This message has a new line\nAnd another\n", ['key' => 'value']);

        // Then
        $log_lines = file($this->logfile);
        $this->assertEquals(1, count($log_lines));
    }

    /**
     * @testCase Log lines will be on a single line even if there are newline characters in the log message.
     */
    public function testLogMessageIsOneLineEvenThoughItHasNewLineCharactersInData()
    {
        // When
        $this->logger->info('Log message', ['key' => "Value\nwith\new\lines\n"]);

        // Then
        $log_lines = file($this->logfile);
        $this->assertEquals(1, count($log_lines));
    }

    /**
     * @testCase Log lines will be on a single line even if there are newline characters in the exception.
     */
    public function testLogMessageIsOneLineEvenThoughItHasNewLineCharactersInException()
    {
        // When
        $this->logger->info('Log message', ['key' => 'value', 'exception' => new \Exception("This\nhas\newlines\nin\nit")]);

        // Then
        $log_lines = file($this->logfile);
        $this->assertEquals(1, count($log_lines));
    }

    /**
     * @testCase Minimum log levels determine what log levels get logged.
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
        $log_lines = file($this->logfile);
        $this->assertEquals(4, count($log_lines));
    }

    /**
     * @testCase Minimum log levels determine what log levels get logged.
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
        $this->assertFalse(file_exists($this->logfile));

        $this->logger->error('This will be logged.');
        $this->assertTrue(file_exists($this->logfile));
    }

    /**
     * @testCase Minimum log levels determine what log levels get logged.
     */
    public function testMinimumLogLevelsByCheckingFileExistsAboveLogLevel()
    {
        // Given
        $this->logger->setLogLevel(LogLevel::ERROR);

        // When
        $this->logger->error('This will be logged.');

        // Then
        $this->assertTrue(file_exists($this->logfile));
    }

    /**
     * @testCase Exception is thrown if the log file cannot be opened.
     * @throws   \Exception
     */
    public function testLogExceptionCannotOpenFile()
    {
        // Given
        $bad_logger = new Logger('/this/file/should/not/exist/on/any/system/if/it/does/well/oh/well/this/test/will/fail/logfile123.loglog.log', self::TEST_CHANNEL);

        // Then
        $this->expectException(\RuntimeException::class);

        // When
        $bad_logger->info('This is not going to work, hence the test for the exception!');
    }

    /**
     * @testCase After setting output to true the logger will output log lines to STDOUT.
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
     * @testCase Time should be in YYYY-MM-DD HH:mm:SS.uuuuuu format.
     * @throws   \Exception
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
