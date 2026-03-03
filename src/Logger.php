<?php
namespace SimpleLog;

use Psr\Log\InvalidArgumentException;
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
 *   $logger->setStdout(true);
 *
 * To change the channel after construction:
 *   $logger->setChannel('newname')
 */
final class Logger implements \Psr\Log\LoggerInterface
{
    /**
     * File name and path of log file.
     */
    private readonly string $logFile;

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
        self::LOG_LEVEL_NONE => PHP_INT_MAX,
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
        if ($logFile === '') {
            throw new \InvalidArgumentException('Log file path cannot be empty.');
        }

        $logDirectory = \dirname($logFile);
        if (!\is_dir($logDirectory)) {
            throw new \InvalidArgumentException("Log file directory does not exist: $logDirectory");
        }

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
            throw new InvalidArgumentException("Log level $logLevel is not a valid log level. Must be one of (" . \implode(', ', \array_keys(self::LEVELS)) . ')');
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
    public function setStdout(bool $stdout): void
    {
        $this->stdout = $stdout;
    }

    /**
     * Log a debug message.
     * Detailed debug information.
     *
     * @param string|\Stringable $message Content of log event.
     * @param mixed[]            $context Associative array of contextual support data that goes with the log event.
     */
    public function debug(string|\Stringable $message = '', array $context = []): void
    {
        $this->log(LogLevel::DEBUG, $message, $context);
    }

    /**
     * Log an info message.
     * Interesting events.
     *
     * Example: User logs in, SQL logs.
     *
     * @param string|\Stringable $message Content of log event.
     * @param mixed[]            $context Associative array of contextual support data that goes with the log event.
     */
    public function info(string|\Stringable $message = '', array $context = []): void
    {
        $this->log(LogLevel::INFO, $message, $context);
    }

    /**
     * Log a notice message.
     * Normal but significant events.
     *
     * @param string|\Stringable $message Content of log event.
     * @param mixed[]            $context Associative array of contextual support data that goes with the log event.
     */
    public function notice(string|\Stringable $message = '', array $context = []): void
    {
        $this->log(LogLevel::NOTICE, $message, $context);
    }

    /**
     * Log a warning message.
     * Exceptional occurrences that are not errors.
     *
     * Example: Use of deprecated APIs, poor use of an API, undesirable things that are not necessarily wrong.
     *
     * @param string|\Stringable $message Content of log event.
     * @param mixed[]            $context Associative array of contextual support data that goes with the log event.
     */
    public function warning(string|\Stringable $message = '', array $context = []): void
    {
        $this->log(LogLevel::WARNING, $message, $context);
    }

    /**
     * Log an error message.
     * Runtime errors that do not require immediate action but should typically be logged and monitored.
     *
     * @param string|\Stringable $message Content of log event.
     * @param mixed[]            $context Associative array of contextual support data that goes with the log event.
     */
    public function error(string|\Stringable $message = '', array $context = []): void
    {
        $this->log(LogLevel::ERROR, $message, $context);
    }

    /**
     * Log a critical condition.
     * Critical conditions.
     *
     * Example: Application component unavailable, unexpected exception.
     *
     * @param string|\Stringable $message Content of log event.
     * @param mixed[]            $context Associative array of contextual support data that goes with the log event.
     */
    public function critical(string|\Stringable $message = '', array $context = []): void
    {
        $this->log(LogLevel::CRITICAL, $message, $context);
    }

    /**
     * Log an alert.
     * Action must be taken immediately.
     *
     * Example: Entire website down, database unavailable, etc.
     * This should trigger the SMS alerts and wake you up.
     *
     * @param string|\Stringable $message Content of log event.
     * @param mixed[]            $context Associative array of contextual support data that goes with the log event.
     */
    public function alert(string|\Stringable $message = '', array $context = []): void
    {
        $this->log(LogLevel::ALERT, $message, $context);
    }

    /**
     * Log an emergency.
     * System is unusable.
     *
     * @param string|\Stringable $message Content of log event.
     * @param mixed[]            $context Associative array of contextual support data that goes with the log event.
     */
    public function emergency(string|\Stringable $message = '', array $context = []): void
    {
        $this->log(LogLevel::EMERGENCY, $message, $context);
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
        if (!\is_string($level) || !\array_key_exists($level, self::LEVELS)) {
            throw new InvalidArgumentException("Log level " . (\is_string($level) ? $level : \gettype($level)) . " is not a valid log level. Must be one of (" . \implode(', ', \array_keys(self::LEVELS)) . ')');
        }

        if (!$this->logAtThisLevel($level)) {
            return;
        }

        // Build log line
        $pid                = \getmypid() ?: -1;
        /** @var string $exception */
        /** @var mixed[] $data */
        [$exception, $data] = $this->handleException($context);
        $data               = $this->encodeData($data);
        $message            = $this->interpolate((string) $message, $context);
        $logLine            = $this->formatLogLine($level, $pid, $message, $data, $exception);

        // Log to file
        $result = @\file_put_contents($this->logFile, $logLine, \FILE_APPEND | \LOCK_EX);
        if ($result === false) {
            $error  = \error_get_last();
            $reason = $error['message'] ?? 'unknown error';
            throw new \RuntimeException("Could not write to log file {$this->logFile} for SimpleLog channel {$this->channel}: {$reason}");
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
     * @param  mixed[] $context
     *
     * @return mixed[]  [exception, data (without exception)]
     */
    private function handleException(array $context): array
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
     * JSON encode the context data array.
     * If encoding fails (e.g. due to resources or circular references), retry with
     * JSON_PARTIAL_OUTPUT_ON_ERROR to preserve serializable values, and add an error indicator.
     *
     * @param  mixed[] $data
     *
     * @return string JSON-encoded context data
     */
    private function encodeData(array $data): string
    {
        if (!$data) {
            return '{}';
        }

        $encoded = \json_encode($data, \JSON_UNESCAPED_SLASHES);
        if ($encoded !== false) {
            return $encoded;
        }

        $errorMessage = \json_last_error_msg();
        $data['_json_encode_error'] = $errorMessage;

        $encoded = \json_encode($data, \JSON_UNESCAPED_SLASHES | \JSON_PARTIAL_OUTPUT_ON_ERROR);

        return $encoded ?: '{"_json_encode_error":"' . $errorMessage . '"}';
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
        return $exceptionData ?: '{"message":' . \json_encode($e->getMessage()) . '}';
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
        $channel = $this->sanitize($this->channel);

        return
            $this->getTime()                    . self::TAB .
            "[$level]"                          . self::TAB .
            "[$channel]"                        . self::TAB .
            "[pid:$pid]"                        . self::TAB .
            $this->sanitize(trim($message))     . self::TAB .
            $this->sanitize($data)              . self::TAB .
            $this->sanitize($exceptionData)     . \PHP_EOL;
    }

    /**
     * Interpolate context values into message placeholders.
     * PSR-3 specifies that context values should be interpolatable into the message
     * using {placeholder} syntax.
     *
     * @param  string  $message
     * @param  mixed[] $context
     *
     * @return string
     */
    private function interpolate(string $message, array $context): string
    {
        $replace = [];
        foreach ($context as $key => $val) {
            if (!\is_array($val) && (!\is_object($val) || $val instanceof \Stringable)) {
                $replace['{' . $key . '}'] = $val;
            }
        }

        return \strtr($message, $replace);
    }

    /**
     * Sanitize a string for safe inclusion in a TSV log line.
     * Replaces tab, newline, and carriage return characters with spaces.
     *
     * @param  string $value
     *
     * @return string
     */
    private function sanitize(string $value): string
    {
        return \str_replace(["\t", "\n", "\r"], '   ', $value);
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
