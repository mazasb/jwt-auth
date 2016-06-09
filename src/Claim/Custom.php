<?php

namespace JwtAuth\Claim;

class Custom extends Claim
{
    /**
     * The claim name.
     *
     * @var string
     */
    private $name;

    /**
     * @param string $name
     * @param mixed $value
     */
    public function __construct($name, $value)
    {
        $this->name = $name;
        parent::__construct($value);
    }

    /**
     * @inheritDoc
     */
    public function getName()
    {
        return $this->name;
    }
}