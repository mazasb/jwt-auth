<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace JWTAuth\Contracts\Http;

use Symfony\Component\HttpFoundation\Request;

interface Parser
{
    /**
     * Parse the request.
     *
     * @param  \Symfony\Component\HttpFoundation\Request  $request
     *
     * @return null|string
     */
    public function parse(Request $request);
}
