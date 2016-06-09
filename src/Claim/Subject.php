<?php

namespace JWTAuth\Claim;

final class Subject extends Claim
{
    const NAME = 'sub';

    /**
     * @inheritDoc
     */
    public function getName()
    {
        return self::NAME;
    }
}
