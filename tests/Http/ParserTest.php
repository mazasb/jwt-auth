<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace JWTAuth\Test\Http;

use Mockery;
//use Illuminate\Http\Request;
//use Illuminate\Routing\Route;
use Symfony\Component\HttpFoundation\Request;
use JWTAuth\Http\Parser\Parser;
use JWTAuth\Http\Parser\Cookies;
use JWTAuth\Test\AbstractTestCase;
use JWTAuth\Http\Parser\AuthHeaders;
use JWTAuth\Http\Parser\QueryString;

class ParserTest extends AbstractTestCase
{
    /** @test */
    public function it_should_return_the_token_from_the_authorization_header()
    {
        $request = Request::create('foo', 'POST');
        $request->headers->set('Authorization', 'Bearer foobar');

        $parser = new Parser($request);

        $parser->setChain([
            new QueryString,
            new AuthHeaders,
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_return_the_token_from_the_prefixed_authentication_header()
    {
        $request = Request::create('foo', 'POST');
        $request->headers->set('Authorization', 'Custom foobar');

        $parser = new Parser($request);

        $parser->setChain([
            new QueryString,
            (new AuthHeaders())->setHeaderPrefix('Custom'),
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_return_the_token_from_the_custom_authentication_header()
    {
        $request = Request::create('foo', 'POST');
        $request->headers->set('custom_authorization', 'Bearer foobar');

        $parser = new Parser($request);

        $parser->setChain([
            new QueryString,
            (new AuthHeaders())->setHeaderName('custom_authorization'),
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_return_the_token_from_the_alt_authorization_headers()
    {
        $request1 = Request::create('foo', 'POST');
        $request1->server->set('HTTP_AUTHORIZATION', 'Bearer foobar');

        $request2 = Request::create('foo', 'POST');
        $request2->server->set('REDIRECT_HTTP_AUTHORIZATION', 'Bearer foobarbaz');

        $parser = new Parser($request1, [
            new AuthHeaders,
            new QueryString,
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());

        $parser->setRequest($request2);
        $this->assertSame($parser->parseToken(), 'foobarbaz');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_return_the_token_from_query_string()
    {
        $request = Request::create('foo', 'GET', ['token' => 'foobar']);

        $parser = new Parser($request);
        $parser->setChain([
            new AuthHeaders,
            new QueryString,
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_return_the_token_from_the_custom_query_string()
    {
        $request = Request::create('foo', 'GET', ['custom_token_key' => 'foobar']);

        $parser = new Parser($request);
        $parser->setChain([
            new AuthHeaders,
            (new QueryString)->setKey('custom_token_key'),
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_return_the_token_from_the_query_string_not_the_input_source()
    {
        $request = Request::create('foo?token=foobar', 'POST', [], [], [], [], json_encode(['token' => 'foobarbaz']));

        $parser = new Parser($request);
        $parser->setChain([
            new AuthHeaders,
            new QueryString,
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_return_the_token_from_the_custom_query_string_not_the_custom_input_source()
    {
        $request = Request::create('foo?custom_token_key=foobar', 'POST', [], [], [], [], json_encode(['custom_token_key' => 'foobarbaz']));

        $parser = new Parser($request);
        $parser->setChain([
            new AuthHeaders,
            (new QueryString)->setKey('custom_token_key'),
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_return_the_token_from_a_cookie()
    {
        $request = Request::create('foo', 'POST', [], ['token' => 'foobar']);

        $parser = new Parser($request);
        $parser->setChain([
            new AuthHeaders,
            new QueryString,
            new Cookies,
        ]);

        $this->assertSame($parser->parseToken(), 'foobar');
        $this->assertTrue($parser->hasToken());
    }

    /** @test */
    public function it_should_ignore_routeless_requests()
    {
        $request = Request::create('foo', 'GET', ['foo' => 'bar']);

        $parser = new Parser($request);
        $parser->setChain([
            new AuthHeaders,
            new QueryString,
        ]);

        $this->assertNull($parser->parseToken());
        $this->assertFalse($parser->hasToken());
    }

    /** @test */
    public function it_should_return_null_if_no_token_in_request()
    {
        $request = Request::create('foo', 'GET', ['foo' => 'bar']);

        $parser = new Parser($request);
        $parser->setChain([
            new AuthHeaders,
            new QueryString,
        ]);

        $this->assertNull($parser->parseToken());
        $this->assertFalse($parser->hasToken());
    }

    /** @test */
    public function it_should_retrieve_the_chain()
    {
        $chain = [
            new AuthHeaders,
            new QueryString,
        ];

        $parser = new Parser(Mockery::mock(Request::class));
        $parser->setChain($chain);

        $this->assertSame($parser->getChain(), $chain);
    }

    /** @test */
    public function it_should_retrieve_the_chain_with_alias()
    {
        $chain = [
            new AuthHeaders,
            new QueryString,
        ];

        $parser = new Parser(Mockery::mock(Request::class));
        $parser->setChainOrder($chain);

        $this->assertSame($parser->getChain(), $chain);
    }

    protected function getRouteMock($expectedParameterValue = null, $expectedParameterName = 'token')
    {
        return Mockery::mock(Route::class)
            ->shouldReceive('parameter')
            ->with($expectedParameterName)
            ->andReturn($expectedParameterValue)
            ->getMock();
    }
}
