<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace JWTAuth;

use BadMethodCallException;
use Symfony\Component\HttpFoundation\Request;
use JWTAuth\Http\Parser\Parser;
use JWTAuth\Support\CustomClaims;
use JWTAuth\Contracts\JWTSubject;
use JWTAuth\Exceptions\JWTException;

class JWT
{
    use CustomClaims;

    /**
     * @var \JWTAuth\Manager
     */
    protected $manager;

    /**
     * @var \JWTAuth\Http\Parser\Parser
     */
    protected $parser;

    /**
     * @var \JWTAuth\Token
     */
    protected $token;

    /**
     * @param  \JWTAuth\Manager  $manager
     * @param  \JWTAuth\Http\Parser\Parser  $parser
     *
     * @return void
     */
    public function __construct(Manager $manager, Parser $parser)
    {
        $this->manager = $manager;
        $this->parser = $parser;
    }

    /**
     * Generate a token using the user identifier as the subject claim.
     *
     * @param  \JWTAuth\Contracts\JWTSubject  $user
     *
     * @return string
     */
    public function fromUser(JWTSubject $user)
    {
        $payload = $this->makePayload($user);

        return $this->manager->encode($payload)->get();
    }

    /**
     * Refresh an expired token.
     *
     * @return string
     */
    public function refresh()
    {
        $this->requireToken();

        return $this->manager->customClaims($this->getCustomClaims())->refresh($this->token)->get();
    }

    /**
     * Invalidate a token (add it to the blacklist).
     *
     * @param  bool  $forceForever
     *
     * @return bool
     */
    public function invalidate($forceForever = false)
    {
        $this->requireToken();

        return $this->manager->invalidate($this->token, $forceForever);
    }

    /**
     * Alias to get the payload, and as a result checks that
     * the token is valid i.e. not expired or blacklisted.
     *
     * @throws \JWTAuth\Exceptions\JWTException
     *
     * @return \JWTAuth\Payload
     */
    public function checkOrFail()
    {
        return $this->getPayload();
    }

    /**
     * Check that the token is valid.
     *
     * @return bool
     */
    public function check()
    {
        try {
            $this->checkOrFail();
        } catch (JWTException $e) {
            return false;
        }

        return true;
    }

    /**
     * Get the token.
     *
     * @return \JWTAuth\Token|false
     */
    public function getToken()
    {
        if (! $this->token) {
            try {
                $this->parseToken();
            } catch (JWTException $e) {
                return false;
            }
        }

        return $this->token;
    }

    /**
     * Parse the token from the request.
     *
     * @throws \JWTAuth\Exceptions\JWTException
     *
     * @return $this
     */
    public function parseToken()
    {
        if (! $token = $this->parser->parseToken()) {
            throw new JWTException('The token could not be parsed from the request');
        }

        return $this->setToken($token);
    }

    /**
     * Get the raw Payload instance.
     *
     * @return \JWTAuth\Payload
     */
    public function getPayload()
    {
        $this->requireToken();

        return $this->manager->decode($this->token);
    }

    /**
     * Alias for getPayload().
     *
     * @return \JWTAuth\Payload
     */
    public function payload()
    {
        return $this->getPayload();
    }

    /**
     * Create a Payload instance.
     *
     * @param  \JWTAuth\Contracts\JWTSubject  $user
     *
     * @return \JWTAuth\Payload
     */
    public function makePayload(JWTSubject $user)
    {
        return $this->factory()->customClaims($this->getClaimsArray($user))->make();
    }

    /**
     * Build the claims array and return it.
     *
     * @param  \JWTAuth\Contracts\JWTSubject  $user
     *
     * @return array
     */
    protected function getClaimsArray(JWTSubject $user)
    {
        return array_merge(
            ['sub' => $user->getJWTIdentifier()],
            $this->customClaims,
            $user->getJWTCustomClaims()
        );
    }

    /**
     * Set the token.
     *
     * @param  \JWTAuth\Token|string  $token
     *
     * @return $this
     */
    public function setToken($token)
    {
        $this->token = $token instanceof Token ? $token : new Token($token);

        return $this;
    }

    /**
     * Unset the current token.
     *
     * @return $this
     */
    public function unsetToken()
    {
        $this->token = null;

        return $this;
    }

    /**
     * Ensure that a token is available.
     *
     * @throws \JWTAuth\Exceptions\JWTException
     *
     * @return void
     */
    protected function requireToken()
    {
        if (! $this->token) {
            throw new JWTException('A token is required');
        }
    }

    /**
     * Set the request instance.
     *
     * @param  \Symfony\Component\HttpFoundation\Request  $request
     *
     * @return $this
     */
    public function setRequest(Request $request)
    {
        $this->parser->setRequest($request);

        return $this;
    }

    /**
     * Get the Manager instance.
     *
     * @return \JWTAuth\Manager
     */
    public function manager()
    {
        return $this->manager;
    }

    /**
     * Get the Parser instance.
     *
     * @return \JWTAuth\Http\Parser\Parser
     */
    public function parser()
    {
        return $this->parser;
    }

    /**
     * Get the Payload Factory.
     *
     * @return \JWTAuth\Factory
     */
    public function factory()
    {
        return $this->manager->getPayloadFactory();
    }

    /**
     * Get the Blacklist.
     *
     * @return \JWTAuth\Blacklist
     */
    public function blacklist()
    {
        return $this->manager->getBlacklist();
    }

    /**
     * Magically call the JWT Manager.
     *
     * @param  string  $method
     * @param  array  $parameters
     *
     * @throws \BadMethodCallException
     *
     * @return mixed
     */
    public function __call($method, $parameters)
    {
        if (method_exists($this->manager, $method)) {
            return call_user_func_array([$this->manager, $method], $parameters);
        }

        throw new BadMethodCallException("Method [$method] does not exist.");
    }
}
