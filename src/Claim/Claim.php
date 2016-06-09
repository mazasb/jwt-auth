<?php

namespace JWTAuth\Claim;

use JsonSerializable;
use Illuminate\Contracts\Support\Jsonable;
use Illuminate\Contracts\Support\Arrayable;

abstract class Claim implements Arrayable, Jsonable, JsonSerializable
{
    /**
     * The claim value.
     *
     * @var mixed
     */
    protected $value;

    /**
     * @param $value
     */
    public function __construct($value)
    {
        $name = $this->getName();
        if (empty($name) || !is_string($name))
        {
            throw new \InvalidArgumentException('Claim name must be not empty string.');
        }

        $this->validate($value);
        $this->value = $value;
    }

    /**
     * @param mixed $value
     */
    protected function validate($value)
    {
    }

    /**
     * Get the claim name.
     *
     * @return string
     */
    abstract public function getName();

    /**
     * Get the claim value.
     *
     * @return mixed
     */
    public function getValue()
    {
        return $this->value;
    }

    /**
     * Convert the object into something JSON serializable.
     *
     * @return array
     */
    public function jsonSerialize()
    {
        return $this->toArray();
    }

    /**
     * Build a key value array comprising of the claim name and value.
     *
     * @return array
     */
    public function toArray()
    {
        return [$this->name => $this->value];
    }

    /**
     * Get the claim as JSON.
     *
     * @param  int  $options
     *
     * @return string
     */
    public function toJson($options = JSON_UNESCAPED_SLASHES)
    {
        return json_encode($this->toArray(), $options);
    }

    /**
     * Get the payload as a string.
     *
     * @return string
     */
    public function __toString()
    {
        return $this->toJson();
    }
}
