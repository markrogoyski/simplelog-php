# SimpleLog Change Log

## v3.0.0

Updated for PHP 8.1 and modern PSR log support.

- PHP minimum version 8.1.
- Requires `psr/log` ^3.0 (dropped 2.0 support).
- `setOutput()` renamed to `setStdout()` for clarity.
- Improved log file locking.
- Input sanitization.
- Uses `Psr\Log\InvalidArgumentException` for invalid log levels.

## v2.1.0 - 2024-11-05

- Add `psr/log` 3.0.* support.
- `psr/log` 2.0.* still supported with Composer `||` conditional

## v2.0.0 - 2024-02-25

Updated for PHP and PSR log version updates.

- PHP minimum version 8.0.
- Implements `psr/log` 2.0.*

## v1.0.0 - 2023-09-09

First official release.

- PHP minimum version 7.4.
- Implements `psr/log` 1.1.*

## v0.4.0 - 2019-08-10

First stable release.

- PHP minimum version 7.0.
- Implements `psr/log` 1.1.*
