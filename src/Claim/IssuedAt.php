<?php

namespace JWTAuth\Claim;

use JWTAuth\Exceptions\InvalidClaimException;
use JWTAuth\Support\Utils;

final class IssuedAt extends DateTime
{
    const NAME = 'iat';

    /**
     * @inheritDoc
     */
    public function getName()
    {
        return self::NAME;
    }

    /**
     * @inheritDoc
     */
    protected function validate($timestamp)
    {
        parent::validate($timestamp);
        if (Utils::isFuture($timestamp))
        {
            throw new InvalidClaimException('IssuedAt value cannot set future timestamp.');
        }
    }
}
