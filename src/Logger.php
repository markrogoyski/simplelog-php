<?php
namespace SimpleLog;

use Psr\Log\LogLevel;

/**
 * Simple Logger
 * Powerful PSR-3 logging so easy it's simple!
 *
 * Implements PHP Standard Recommendation interface: PSR-3 \Psr\Log\LoggerInterface
 *
 * Log the following severities: debug, info, notice, warning, error, critical, alert, emergency.
 * Log format: YYYY-mm-dd HH:ii:ss.uuuuuu  [loglevel]  [channel]  [pid:##]  Log message content  {"Optional":"JSON Contextual Support Data"}  {"Optional":"Exception Data"}
 *
 * Standard usage - default options:
 *   $logger = new SimpleLog\Logger('logfile.log', 'channelname');
 *   $logger->info('Normal informational event happened.');
 *   $logger->error('Something bad happened.', ['key1' => 'value that gives context', 'key2' => 'some more context', 'exception' => $e]);
 *
 * Optional constructor option: Set default lowest log level (Example error and above):
 *   $logger = new SimpleLog\Logger('logfile.log', 'channelname', \Psr\Log\LogLevel::ERROR);
 *   $logger->error('This will get logged');
 *   $logger->info('This is below the minimum log level and will not get logged');
 *
 * To log an exception, set as data context array key 'exception'
 *   $logger->error('Something exceptional happened.', ['exception' => $e]);
 *
 * To set output to standard out (STDOUT) as well as a log file:
 *   $logger->setOutput(true);
 *
 * To change the channel after construction:
 *   $logger->setChannel('newname')
 */
class Logger implements \Psr\Log\LoggerInterface
{
    /**
     * File name and path of log file.
     * @var string
     */
    private string $logFile;

    /**
     * Log channel--namespace for log lines.
     * Used to identify and correlate groups of similar log lines.
     * @var string
     */
    private string $channel;

    /**
     * Lowest log level to log.
     * @var int
     */
    private int $logLevel;

    /**
     * Whether to log to standard out.
     * @var bool
     */
    private bool $stdout;

    /**
     * Log fields separated by tabs to form a TSV (CSV with tabs).
     */
    private const TAB = "\t";

    /**
     * Special minimum log level which will not log any log levels.
     */
    public const LOG_LEVEL_NONE = 'none';

    /**
     * Log level hierarchy
     */
    public const LEVELS = [
        self::LOG_LEVEL_NONE => -1,
        LogLevel::DEBUG      => 0,
        LogLevel::INFO       => 1,
        LogLevel::NOTICE     => 2,
        LogLevel::WARNING    => 3,
        LogLevel::ERROR      => 4,
        LogLevel::CRITICAL   => 5,
        LogLevel::ALERT      => 6,
        LogLevel::EMERGENCY  => 7,
    ];

    /**
     * @param string $logFile  File name and path of log file.
     * @param string $channel  Logger channel associated with this logger.
     * @param string $logLevel (optional) Lowest log level to log.
     */
    public function __construct(string $logFile, string $channel, string $logLevel = LogLevel::DEBUG)
    {
        $this->logFile  = $logFile;
        $this->channel   = $channel;
        $this->stdout    = false;
        $this->setLogLevel($logLevel);
    }

    /**
     * Set the lowest log level to log.
     *
     * @param string $logLevel
     */
    public function setLogLevel(string $logLevel): void
    {
        if (!\array_key_exists($logLevel, self::LEVELS)) {
            throw new \DomainException("Log level $logLevel is not a valid log level. Must be one of (" . \implode(', ', \array_keys(self::LEVELS)) . ')');
        }

        $this->logLevel = self::LEVELS[$logLevel];
    }

    /**
     * Set the log channel which identifies the log line.
     *
     * @param string $channel
     */
    public function setChannel(string $channel): void
    {
        $this->channel = $channel;
    }

    /**
     * Set the standard out option on or off.
     * If set to true, log lines will also be printed to standard out.
     *
     * @param bool $stdout
     */
    public function setOutput(bool $stdout): void
    {
        $this->stdout = $stdout;
    }

    /**
     * Log a debug message.
     * Fine-grained informational events that are most useful to debug an application.
     *
     * @param string|\Stringable $message Content of log event.
     * @param mixed[]            $context Associative array of contextual support data that goes with the log event.
     *
     * @throws \RuntimeException
     */
    public function debug(string|\Stringable $message = '', array $context = []): void
    {
        if ($this->logAtThisLevel(LogLevel::DEBUG)) {
            $this->log(LogLevel::DEBUG, $message, $context);
        }
    }

    /**
     * Log an info message.
     * Interesting events and informational messages that highlight the progress of the application at coarse-grained level.
     *
     * @param string|\Stringable $message Content of log event.
     * @param mixed[]            $context Associative array of contextual support data that goes with the log event.
     *
     * @throws \RuntimeException
     */
    public function info(string|\Stringable $message = '', array $context = []): void
    {
        if ($this->logAtThisLevel(LogLevel::INFO)) {
            $this->log(LogLevel::INFO, $message, $context);
        }
    }

    /**
     * Log an notice message.
     * Normal but significant events.
     *
     * @param string|\Stringable $message Content of log event.
     * @param mixed[]            $context Associative array of contextual support data that goes with the log event.
     *
     * @throws \RuntimeException
     */
    public function notice(string|\Stringable $message = '', array $context = []): void
    {
        if ($this->logAtThisLevel(LogLevel::NOTICE)) {
            $this->log(LogLevel::NOTICE, $message, $context);
        }
    }

    /**
     * Log a warning message.
     * Exceptional occurrences that are not errors--undesirable things that are not necessarily wrong.
     * Potentially harmful situations which still allow the application to continue running.
     *
     * @param string|\Stringable $message Content of log event.
     * @param mixed[]            $context Associative array of contextual support data that goes with the log event.
     *
     * @throws \RuntimeException
     */
    public function warning(string|\Stringable $message = '', array $context = []): void
    {
        if ($this->logAtThisLevel(LogLevel::WARNING)) {
            $this->log(LogLevel::WARNING, $message, $context);
        }
    }

    /**
     * Log an error message.
     * Error events that might still allow the application to continue running.
     * Runtime errors that do not require immediate action but should typically be logged and monitored.
     *
     * @param string|\Stringable $message Content of log event.
     * @param mixed[]            $context Associative array of contextual support data that goes with the log event.
     *
     * @throws \RuntimeException
     */
    public function error(string|\Stringable $message = '', array $context = []): void
    {
        if ($this->logAtThisLevel(LogLevel::ERROR)) {
            $this->log(LogLevel::ERROR, $message, $context);
        }
    }

    /**
     * Log a critical condition.
     * Application components being unavailable, unexpected exceptions, etc.
     *
     * @param string|\Stringable $message Content of log event.
     * @param mixed[]            $context Associative array of contextual support data that goes with the log event.
     *
     * @throws \RuntimeException
     */
    public function critical(string|\Stringable $message = '', array $context = []): void
    {
        if ($this->logAtThisLevel(LogLevel::CRITICAL)) {
            $this->log(LogLevel::CRITICAL, $message, $context);
        }
    }

    /**
     * Log an alert.
     * This should trigger an email or SMS alert and wake you up.
     * Example: Entire site down, database unavailable, etc.
     *
     * @param string|\Stringable $message Content of log event.
     * @param mixed[]            $context Associative array of contextual support data that goes with the log event.
     *
     * @throws \RuntimeException
     */
    public function alert(string|\Stringable $message = '', array $context = []): void
    {
        if ($this->logAtThisLevel(LogLevel::ALERT)) {
            $this->log(LogLevel::ALERT, $message, $context);
        }
    }

    /**
     * Log an emergency.
     * System is unusable.
     * This should trigger an email or SMS alert and wake you up.
     *
     * @param string|\Stringable $message Content of log event.
     * @param mixed[]            $context Associative array of contextual support data that goes with the log event.
     *
     * @throws \RuntimeException
     */
    public function emergency(string|\Stringable $message = '', array $context = []): void
    {
        if ($this->logAtThisLevel(LogLevel::EMERGENCY)) {
            $this->log(LogLevel::EMERGENCY, $message, $context);
        }
    }

    /**
     * Log a message.
     * Generic log routine that all severity levels use to log an event.
     *
     * @param mixed              $level   Log level
     * @param string|\Stringable $message Content of log event.
     * @param mixed[]            $context Associative array of contextual support data that goes with the log event.
     *
     * @throws \RuntimeException when log file cannot be opened for writing.
     */
    public function log($level, string|\Stringable $message = '', array $context = []): void
    {
        /** @var string $level */

        // Build log line
        $pid                = \getmypid() ?: -1;
        /** @var string $exception */
        [$exception, $data] = $this->handleException($context);
        $data               = $data ? \json_encode($data, \JSON_UNESCAPED_SLASHES) : '{}';
        $data               = $data ?: '{}'; // Fail-safe in case json_encode fails.
        $logLine            = $this->formatLogLine($level, $pid, $message, $data, $exception);

        // Log to file
        try {
            $fh = \fopen($this->logFile, 'a');
            if ($fh === false) {
                throw new \RuntimeException('fopen failed');
            }
            \fwrite($fh, $logLine);
            \fclose($fh);
        } catch (\Throwable $e) {
            throw new \RuntimeException("Could not open log file {$this->logFile} for writing to SimpleLog channel {$this->channel}!", 0, $e);
        }

        // Log to stdout if option set to do so.
        if ($this->stdout) {
            print($logLine);
        }
    }

    /**
     * Determine if the logger should log at a certain log level.
     *
     * @param  string $level
     *
     * @return bool True if we log at this level; false otherwise.
     */
    private function logAtThisLevel(string $level): bool
    {
        return self::LEVELS[$level] >= $this->logLevel;
    }

    /**
     * Handle an exception in the data context array.
     * If an exception is included in the data context array, extract it.
     *
     * @param  mixed[]|null $context
     *
     * @return mixed[]  [exception, data (without exception)]
     */
    private function handleException(array $context = null): array
    {
        if (isset($context['exception']) && $context['exception'] instanceof \Throwable) {
            $exception      = $context['exception'];
            $exception_data = $this->buildExceptionData($exception);
            unset($context['exception']);
        } else {
            $exception_data = '{}';
        }

        return [$exception_data, $context];
    }

    /**
     * Build the exception log data.
     *
     * @param  \Throwable $e
     *
     * @return string JSON {message, code, file, line, trace}
     */
    private function buildExceptionData(\Throwable $e): string
    {
        $exceptionData = \json_encode(
            [
                'message' => $e->getMessage(),
                'code'    => $e->getCode(),
                'file'    => $e->getFile(),
                'line'    => $e->getLine(),
                'trace'   => $e->getTrace()
            ],
            \JSON_UNESCAPED_SLASHES
        );

        // Fail-safe in case json_encode failed
        return $exceptionData ?: '{"message":"' . $e->getMessage() . '"}';
    }

    /**
     * Format the log line.
     * YYYY-mm-dd HH:ii:ss.uuuuuu  [loglevel]  [channel]  [pid:##]  Log message content  {"Optional":"JSON Contextual Support Data"}  {"Optional":"Exception Data"}
     *
     * @param  string $level
     * @param  int    $pid
     * @param  string $message
     * @param  string $data
     * @param  string $exceptionData
     *
     * @return string
     */
    private function formatLogLine(string $level, int $pid, string $message, string $data, string $exceptionData): string
    {
        return
            $this->getTime()                              . self::TAB .
            "[$level]"                                    . self::TAB .
            "[{$this->channel}]"                          . self::TAB .
            "[pid:$pid]"                                  . self::TAB .
            \str_replace(\PHP_EOL, '   ', trim($message))  . self::TAB .
            \str_replace(\PHP_EOL, '   ', $data)           . self::TAB .
            \str_replace(\PHP_EOL, '   ', $exceptionData) . \PHP_EOL;
    }

    /**
     * Get current date time, with microsecond precision.
     * Format: YYYY-mm-dd HH:ii:ss.uuuuuu
     *
     * @return string Date time
     */
    private function getTime(): string
    {
        return (new \DateTimeImmutable('now'))->format('Y-m-d H:i:s.u');
    }
}
