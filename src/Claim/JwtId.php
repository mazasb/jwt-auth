<?php

namespace JWTAuth\Claim;

final class JwtId extends Claim
{
    const NAME = 'jti';

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
    protected function validate($value)
    {
        parent::validate($value);
        if (empty($value) || !is_string($value))
        {
            throw new \InvalidArgumentException('JwtId must be not empty string.');
        }
    }
}
