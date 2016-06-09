<?php

namespace JWTAuth\Claim;

final class NotBefore extends DateTime
{
    const NAME = 'nbf';

    /**
     * @inheritDoc
     */
    public function getName()
    {
        return self::NAME;
    }
}
