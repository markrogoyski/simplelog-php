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
    private $log_file;

    /**
     * Log channel--namespace for log lines.
     * Used to identify and correlate groups of similar log lines.
     * @var string
     */
    private $channel;

    /**
     * Lowest log level to log.
     * @var int
     */
    private $log_level;

    /**
     * Whether to log to standard out.
     * @var bool
     */
    private $stdout;

    /**
     * Log fields separated by tabs to form a TSV (CSV with tabs).
     */
    const TAB = "\t";

    /**
     * Special minimum log level which will not log any log levels.
     */
    const LOG_LEVEL_NONE = 'none';

    /**
     * Log level hierachy
     */
    const LEVELS = [
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
     * Logger constructor
     *
     * @param string $log_file  File name and path of log file.
     * @param string $channel   Logger channel associated with this logger.
     * @param string $log_level (optional) Lowest log level to log.
     */
    public function __construct(string $log_file, string $channel, string $log_level = LogLevel::DEBUG)
    {
        $this->log_file  = $log_file;
        $this->channel   = $channel;
        $this->stdout    = false;
        $this->setLogLevel($log_level);
    }

    /**
     * Set the lowest log level to log.
     *
     * @param string $log_level
     */
    public function setLogLevel(string $log_level)
    {
        if (!array_key_exists($log_level, self::LEVELS)) {
            throw new \DomainException("Log level $log_level is not a valid log level. Must be one of (" . implode(', ', array_keys(self::LEVELS)) . ')');
        }

        $this->log_level = self::LEVELS[$log_level];
    }

    /**
     * Set the log channel which identifies the log line.
     *
     * @param string $channel
     */
    public function setChannel(string $channel)
    {
        $this->channel = $channel;
    }

    /**
     * Set the standard out option on or off.
     * If set to true, log lines will also be printed to standard out.
     *
     * @param bool $stdout
     */
    public function setOutput(bool $stdout)
    {
        $this->stdout = $stdout;
    }

    /**
     * Log a debug message.
     * Fine-grained informational events that are most useful to debug an application.
     *
     * @param string $message Content of log event.
     * @param array $data Associative array of contextual support data that goes with the log event.
     *
     * @throws \RuntimeException
     */
    public function debug($message = '', array $data = null)
    {
        if ($this->logAtThisLevel(LogLevel::DEBUG)) {
            $this->log(LogLevel::DEBUG, $message, $data);
        }
    }

    /**
     * Log an info message.
     * Interesting events and informational messages that highlight the progress of the application at coarse-grained level.
     *
     * @param string $message Content of log event.
     * @param array  $data    Associative array of contextual support data that goes with the log event.
     *
     * @throws \RuntimeException
     */
    public function info($message = '', array $data = null)
    {
        if ($this->logAtThisLevel(LogLevel::INFO)) {
            $this->log(LogLevel::INFO, $message, $data);
        }
    }

    /**
     * Log an notice message.
     * Normal but significant events.
     *
     * @param string $message Content of log event.
     * @param array  $data    Associative array of contextual support data that goes with the log event.
     *
     * @throws \RuntimeException
     */
    public function notice($message = '', array $data = null)
    {
        if ($this->logAtThisLevel(LogLevel::NOTICE)) {
            $this->log(LogLevel::NOTICE, $message, $data);
        }
    }

    /**
     * Log a warning message.
     * Exceptional occurrences that are not errors--undesirable things that are not necessarily wrong.
     * Potentially harmful situations which still allow the application to continue running.
     *
     * @param string $message Content of log event.
     * @param array  $data    Associative array of contextual support data that goes with the log event.
     *
     * @throws \RuntimeException
     */
    public function warning($message = '', array $data = null)
    {
        if ($this->logAtThisLevel(LogLevel::WARNING)) {
            $this->log(LogLevel::WARNING, $message, $data);
        }
    }

    /**
     * Log an error message.
     * Error events that might still allow the application to continue running.
     * Runtime errors that do not require immediate action but should typically be logged and monitored.
     *
     * @param string $message Content of log event.
     * @param array  $data    Associative array of contextual support data that goes with the log event.
     *
     * @throws \RuntimeException
     */
    public function error($message = '', array $data = null)
    {
        if ($this->logAtThisLevel(LogLevel::ERROR)) {
            $this->log(LogLevel::ERROR, $message, $data);
        }
    }

    /**
     * Log a critical condition.
     * Application components being unavailable, unexpected exceptions, etc.
     *
     * @param string $message Content of log event.
     * @param array  $data    Associative array of contextual support data that goes with the log event.
     *
     * @throws \RuntimeException
     */
    public function critical($message = '', array $data = null)
    {
        if ($this->logAtThisLevel(LogLevel::CRITICAL)) {
            $this->log(LogLevel::CRITICAL, $message, $data);
        }
    }

    /**
     * Log an alert.
     * This should trigger an email or SMS alert and wake you up.
     * Example: Entire site down, database unavailable, etc.
     *
     * @param string $message Content of log event.
     * @param array  $data    Associative array of contextual support data that goes with the log event.
     *
     * @throws \RuntimeException
     */
    public function alert($message = '', array $data = null)
    {
        if ($this->logAtThisLevel(LogLevel::ALERT)) {
            $this->log(LogLevel::ALERT, $message, $data);
        }
    }

    /**
     * Log an emergency.
     * System is unsable.
     * This should trigger an email or SMS alert and wake you up.
     *
     * @param string $message Content of log event.
     * @param array  $data    Associative array of contextual support data that goes with the log event.
     *
     * @throws \RuntimeException
     */
    public function emergency($message = '', array $data = null)
    {
        if ($this->logAtThisLevel(LogLevel::EMERGENCY)) {
            $this->log(LogLevel::EMERGENCY, $message, $data);
        }
    }

    /**
     * Log a message.
     * Generic log routine that all severity levels use to log an event.
     *
     * @param string $level   Log level
     * @param string $message Content of log event.
     * @param array  $data    Potentially multidimensional associative array of support data that goes with the log event.
     *
     * @throws \RuntimeException when log file cannot be opened for writing.
     */
    public function log($level, $message = '', array $data = null)
    {
        try {
            // Build log line
            $pid                    = getmypid();
            list($exception, $data) = $this->handleException($data);
            $data                   = $data ? json_encode($data, \JSON_UNESCAPED_SLASHES) : '{}';
            $log_line               = $this->formatLogLine($level, $pid, $message, $data, $exception);

            // Log to file
            $fh = fopen($this->log_file, 'a');
            fwrite($fh, $log_line);
            fclose($fh);

            // Log to stdout if option set to do so.
            if ($this->stdout) {
                print($log_line);
            }
        } catch (\Throwable $e) {
            throw new \RuntimeException("Could not open log file {$this->log_file} for writing to SimpleLog channel {$this->channel}!", 0, $e);
        }
    }

    /**
     * Determine if the logger should log at a certain log level.
     *
     * @param  string $level
     *
     * @return bool True if we log at this level; false otherwise.
     */
    private function logAtThisLevel($level): bool
    {
        return self::LEVELS[$level] >= $this->log_level;
    }

    /**
     * Handle an exception in the data context array.
     * If an exception is included in the data context array, extract it.
     *
     * @param  array  $data
     *
     * @return array  [exception, data (without exception)]
     */
    private function handleException(array $data = null): array
    {
        if (isset($data['exception']) && $data['exception'] instanceof \Throwable) {
            $exception      = $data['exception'];
            $exception_data = $this->buildExceptionData($exception);
            unset($data['exception']);
        } else {
            $exception_data = '{}';
        }

        return [$exception_data, $data];
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
        return json_encode(
            [
                'message' => $e->getMessage(),
                'code'    => $e->getCode(),
                'file'    => $e->getFile(),
                'line'    => $e->getLine(),
                'trace'   => $e->getTrace()
            ],
            \JSON_UNESCAPED_SLASHES
        );
    }

    /**
     * Format the log line.
     * YYYY-mm-dd HH:ii:ss.uuuuuu  [loglevel]  [channel]  [pid:##]  Log message content  {"Optional":"JSON Contextual Support Data"}  {"Optional":"Exception Data"}
     *
     * @param  string $level
     * @param  int    $pid
     * @param  string $message
     * @param  string $data
     * @param  string $exception_data
     *
     * @return string
     */
    private function formatLogLine(string $level, int $pid, string $message, string $data, string $exception_data): string
    {
        return
            $this->getTime()                              . self::TAB .
            "[$level]"                                    . self::TAB .
            "[{$this->channel}]"                          . self::TAB .
            "[pid:$pid]"                                  . self::TAB .
            str_replace(\PHP_EOL, '   ', trim($message))  . self::TAB .
            str_replace(\PHP_EOL, '   ', $data)           . self::TAB .
            str_replace(\PHP_EOL, '   ', $exception_data) . \PHP_EOL;
    }

    /**
     * Get current date time.
     * Format: YYYY-mm-dd HH:ii:ss.uuuuuu
     * Microsecond precision.
     *
     * @return string Date time
     */
    private function getTime(): string
    {
        $microtime          = microtime(true);
        $microtime_formated = sprintf("%06d", ($microtime - floor($microtime) ) * 1000000);
        $dt                 = new \DateTime(date('Y-m-d H:i:s.'.$microtime_formated, $microtime));

        return $dt->format('Y-m-d H:i:s.u');
    }
}
