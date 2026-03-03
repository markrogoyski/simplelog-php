<?php

namespace SimpleLog\Tests\Fixture;

final class StringableMessage implements \Stringable
{
    public function __construct(
        private readonly string $message
    ) {
    }

    public function __toString(): string
    {
        return $this->message;
    }
}
