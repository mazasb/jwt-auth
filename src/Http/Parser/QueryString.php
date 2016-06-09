<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace JWTAuth\Http\Parser;

use Symfony\Component\HttpFoundation\Request;
use JWTAuth\Contracts\Http\Parser as ParserContract;

class QueryString implements ParserContract
{
    /**
     * The query string key.
     *
     * @var string
     */
    protected $key = 'token';

    /**
     * Try to parse the token from the request query string.
     *
     * @param  \Symfony\Component\HttpFoundation\Request  $request
     *
     * @return null|string
     */
    public function parse(Request $request)
    {
        return $request->query->get($this->key);
    }

    /**
     * Set the query string key.
     *
     * @param  string  $key
     *
     * @return $this
     */
    public function setKey($key)
    {
        $this->key = $key;

        return $this;
    }
}
