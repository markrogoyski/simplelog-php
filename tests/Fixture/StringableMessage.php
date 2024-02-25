<?php

namespace SimpleLog\Tests\Fixture;

final class StringableMessage implements \Stringable
{
    private string $message;

    public function __construct(string $message)
    {
        $this->message = $message;
    }

    public function __toString()
    {
        return $this->message;
    }
}
