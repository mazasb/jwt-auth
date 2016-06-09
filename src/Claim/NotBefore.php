<?php

namespace JWTAuth\Claim;

use JWTAuth\Exceptions\InvalidClaimException;
use JWTAuth\Support\Utils;

final class NotBefore extends DateTime
{
    const NAME = 'nbf';

    /**
     * @inheritDoc
     */
    protected function validate($value)
    {
        parent::validate($value);
        if (Utils::isFuture($value))
        {
            throw new InvalidClaimException('NotBefore claim not be a future time.');
        }
    }

    /**
     * @inheritDoc
     */
    public function getName()
    {
        return self::NAME;
    }
}
