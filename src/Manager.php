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

use JWTAuth\Support\RefreshFlow;
use JWTAuth\Support\CustomClaims;
use JWTAuth\Exceptions\JWTException;
use JWTAuth\Exceptions\TokenBlacklistedException;
use JWTAuth\Contracts\Providers\JWT as JWTContract;

class Manager
{
    use RefreshFlow, CustomClaims;

    /**
     * @var \JWTAuth\Contracts\Providers\JWT
     */
    protected $provider;

    /**
     * @var \JWTAuth\Blacklist
     */
    protected $blacklist;

    /**
     * @var \JWTAuth\Factory
     */
    protected $payloadFactory;

    /**
     * @var bool
     */
    protected $blacklistEnabled = true;

    /**
     * @param  \JWTAuth\Contracts\Providers\JWT  $provider
     * @param  \JWTAuth\Blacklist  $blacklist
     * @param  \JWTAuth\Factory  $payloadFactory
     *
     * @return void
     */
    public function __construct(JWTContract $provider, Blacklist $blacklist, Factory $payloadFactory)
    {
        $this->provider = $provider;
        $this->blacklist = $blacklist;
        $this->payloadFactory = $payloadFactory;
    }

    /**
     * Encode a Payload and return the Token.
     *
     * @param  \JWTAuth\Payload  $payload
     *
     * @return \JWTAuth\Token
     */
    public function encode(Payload $payload)
    {
        $token = $this->provider->encode($payload->get());

        return new Token($token);
    }

    /**
     * Decode a Token and return the Payload.
     *
     * @param  \JWTAuth\Token  $token
     *
     * @throws \JWTAuth\Exceptions\TokenBlacklistedException
     *
     * @return \JWTAuth\Payload
     */
    public function decode(Token $token)
    {
        $payloadArray = $this->provider->decode($token->get());

        $payload = $this->payloadFactory
                        ->setRefreshFlow($this->refreshFlow)
                        ->customClaims($payloadArray)
                        ->make();

        if ($this->blacklistEnabled && $this->blacklist->has($payload)) {
            throw new TokenBlacklistedException('The token has been blacklisted');
        }

        return $payload;
    }

    /**
     * Refresh a Token and return a new Token.
     *
     * @param  \JWTAuth\Token  $token
     *
     * @return \JWTAuth\Token
     */
    public function refresh(Token $token)
    {
        $payload = $this->setRefreshFlow()->decode($token);

        if ($this->blacklistEnabled) {
            // invalidate old token
            $this->blacklist->add($payload);
        }

        // persist the subject and issued at claims
        $claims = array_merge(
            $this->customClaims,
            ['sub' => $payload['sub'], 'iat' => $payload['iat']]
        );

        // return the new token
        return $this->encode(
            $this->payloadFactory->customClaims($claims)->make()
        );
    }

    /**
     * Invalidate a Token by adding it to the blacklist.
     *
     * @param  \JWTAuth\Token  $token
     * @param  bool  $forceForever
     *
     * @throws \JWTAuth\Exceptions\JWTException
     *
     * @return bool
     */
    public function invalidate(Token $token, $forceForever = false)
    {
        if (! $this->blacklistEnabled) {
            throw new JWTException('You must have the blacklist enabled to invalidate a token.');
        }

        return call_user_func(
            [$this->blacklist, $forceForever ? 'addForever' : 'add'],
            $this->decode($token)
        );
    }

    /**
     * Get the Payload Factory instance.
     *
     * @return \JWTAuth\Factory
     */
    public function getPayloadFactory()
    {
        return $this->payloadFactory;
    }

    /**
     * Get the JWTProvider instance.
     *
     * @return \JWTAuth\Contracts\Providers\JWT
     */
    public function getJWTProvider()
    {
        return $this->provider;
    }

    /**
     * Get the Blacklist instance.
     *
     * @return \JWTAuth\Blacklist
     */
    public function getBlacklist()
    {
        return $this->blacklist;
    }

    /**
     * Set whether the blacklist is enabled.
     *
     * @param  bool  $enabled
     *
     * @return $this
     */
    public function setBlacklistEnabled($enabled)
    {
        $this->blacklistEnabled = $enabled;

        return $this;
    }
}
