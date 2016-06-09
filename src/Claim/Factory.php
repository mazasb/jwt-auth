<?php

namespace JWTAuth\Claim;

class Factory
{
    /**
     * @var array
     */
    private $classMap;

    /**
     * @param array $additionalClassMap
     */
    public function __construct(array $additionalClassMap = [])
    {
        // TODO: must check constructor is only one argument?
        $this->classMap = array_merge($this->getBaseClassMap(), $additionalClassMap);
    }

    /**
     * Get the instance of the claim when passing the name and value.
     *
     * @param string $name
     * @param mixed $value
     *
     * @return Claim
     */
    public function get($name, $value)
    {
        if ($this->has($name))
        {
            return new $this->classMap[$name]($value);
        }

        return new Custom($name, $value);
    }

    /**
     * Check whether the claim exists.
     *
     * @param string $name
     *
     * @return bool
     */
    public function has($name)
    {
        return array_key_exists($name, $this->classMap);
    }

    /**
     * @return array
     */
    private function getBaseClassMap()
    {
        return [
            Audience::NAME   => Audience::class,
            Expiration::NAME => Expiration::class,
            IssuedAt::NAME   => IssuedAt::class,
            Issuer::NAME     => Issuer::class,
            JwtId::NAME      => JwtId::class,
            NotBefore::NAME  => NotBefore::class,
            Subject::NAME    => Subject::class,
        ];
    }
}
