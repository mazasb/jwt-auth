<?php
/**
 * User: mazasb
 * Date: 2016. 06. 08.
 * Time: 12:57
 */

namespace JWTAuth\Claim;

use DateTimeInterface;
use JWTAuth\Exceptions\InvalidClaimException;

abstract class DateTime extends Claim
{
    /**
     * @inheritDoc
     */
    public function __construct($value)
    {
        if ($value instanceof DateTimeInterface)
        {
            $value = $value->getTimestamp();
        }
        parent::__construct($value);
    }

    /**
     * @inheritDoc
     */
    protected function validate($value)
    {
        parent::validate($value);

        if (!is_int($value))
        {
            throw new InvalidClaimException(sprintf('Timestamp must be integer, %s given.', gettype($value)));
        }
    }
}
