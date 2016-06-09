<?php

namespace JWTAuth\Claim;

final class Issuer extends Claim
{
    const NAME = 'iss';

    /**
     * @inheritDoc
     */
    public function getName()
    {
        return self::NAME;
    }
}
