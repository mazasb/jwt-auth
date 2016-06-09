<?php

namespace JWTAuth\Claim;

final class Audience extends Claim
{
    const NAME = 'aud';

    /**
     * @inheritDoc
     */
    public function getName()
    {
        return self::NAME;
    }
}
