<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Http\Parser;

use Symfony\Component\HttpFoundation\Request;
use Tymon\JWTAuth\Contracts\Http\Parser as ParserContract;

class InputSource implements ParserContract
{
    /**
     * The input source key.
     *
     * @var string
     */
    protected $key = 'token';

    /**
     * Try to parse the token from the request input source.
     *
     * @param  \Symfony\Component\HttpFoundation\Request  $request
     *
     * @return null|string
     */
    public function parse(Request $request)
    {
        return $request->request->get($this->key);
    }

    /**
     * Set the input source key.
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
