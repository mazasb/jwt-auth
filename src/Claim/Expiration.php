<?php

namespace JWTAuth\Claim;

final class Expiration extends DateTime
{
    const NAME = 'exp';

    /**
     * @inheritDoc
     */
    public function getName()
    {
        return self::NAME;
    }
}
