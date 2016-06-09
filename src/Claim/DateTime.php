<?php
/**
 * User: mazasb
 * Date: 2016. 06. 08.
 * Time: 12:57
 */

namespace JWTAuth\Claim;

abstract class DateTime extends Claim
{
    /**
     * @inheritDoc
     */
    protected function validate($value)
    {
        parent::validate($value);

        if (!is_int($value))
        {
            throw new \UnexpectedValueException(sprintf('Timestamp must be integer, %s given.', gettype($value)));
        }
    }
}
