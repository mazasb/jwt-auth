<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace JWTAuth\Test;

use Mockery;
use StdClass;
use JWTAuth\Token;
use JWTAuth\Factory;
use JWTAuth\JWTAuth;
use JWTAuth\Manager;
use JWTAuth\Payload;
use Symfony\Component\HttpFoundation\Request;
use JWTAuth\Http\Parser\Parser;
use JWTAuth\Test\Stubs\UserStub;
use JWTAuth\Exceptions\JWTException;
use JWTAuth\Contracts\Providers\Auth;
use JWTAuth\Exceptions\TokenInvalidException;

class JWTAuthTest extends AbstractTestCase
{
    /**
     * @var \Mockery\MockInterface|\JWTAuth\Manager
     */
    protected $manager;

    /**
     * @var \Mockery\MockInterface|\JWTAuth\Contracts\Providers\Auth
     */
    protected $auth;

    /**
     * @var \Mockery\MockInterface|\JWTAuth\Http\Parser
     */
    protected $parser;

    /**
     * @var \JWTAuth\JWTAuth
     */
    protected $jwtAuth;

    public function setUp()
    {
        $this->manager = Mockery::mock(Manager::class);
        $this->auth = Mockery::mock(Auth::class);
        $this->parser = Mockery::mock(Parser::class);

        $this->jwtAuth = new JWTAuth($this->manager, $this->auth, $this->parser);
    }

    public function tearDown()
    {
        Mockery::close();

        parent::tearDown();
    }

    /** @test */
    public function it_should_return_a_token_when_passing_a_user()
    {
        $payloadFactory = Mockery::mock(Factory::class);
        $payloadFactory->shouldReceive('make')->andReturn(Mockery::mock(Payload::class));

        $this->manager
             ->shouldReceive('getPayloadFactory->customClaims')
             ->once()
             ->with(['sub' => 1, 'foo' => 'bar', 'role' => 'admin'])
             ->andReturn($payloadFactory);

        $this->manager->shouldReceive('encode->get')->once()->andReturn('foo.bar.baz');

        $token = $this->jwtAuth->fromUser(new UserStub);

        $this->assertSame($token, 'foo.bar.baz');
    }

    /** @test */
    public function it_should_return_a_token_when_passing_valid_credentials_to_attempt_method()
    {
        $payloadFactory = Mockery::mock(Factory::class);
        $payloadFactory->shouldReceive('make')->andReturn(Mockery::mock(Payload::class));

        $this->manager
             ->shouldReceive('getPayloadFactory->customClaims')
             ->once()
             ->with(['sub' => 1, 'foo' => 'bar', 'role' => 'admin'])
             ->andReturn($payloadFactory);

        $this->manager->shouldReceive('encode->get')->once()->andReturn('foo.bar.baz');

        $this->auth->shouldReceive('byCredentials')->once()->andReturn(true);
        $this->auth->shouldReceive('user')->once()->andReturn(new UserStub);

        $token = $this->jwtAuth->attempt(['foo' => 'bar']);

        $this->assertSame($token, 'foo.bar.baz');
    }

    /** @test */
    public function it_should_return_false_when_passing_invalid_credentials_to_attempt_method()
    {
        $this->manager->shouldReceive('encode->get')->never();
        $this->auth->shouldReceive('byCredentials')->once()->andReturn(false);
        $this->auth->shouldReceive('user')->never();

        $token = $this->jwtAuth->attempt(['foo' => 'bar']);

        $this->assertFalse($token);
    }

    /**
     * @test
     * @expectedException \JWTAuth\Exceptions\JWTException
     */
    public function it_should_throw_an_exception_when_not_providing_a_token()
    {
        $this->jwtAuth->toUser();
    }

    /** @test */
    public function it_should_return_the_owning_user_from_a_token_containing_an_existing_user()
    {
        $payload = Mockery::mock(Payload::class);
        $payload->shouldReceive('get')->once()->with('sub')->andReturn(1);

        $this->manager->shouldReceive('decode')->once()->andReturn($payload);

        $this->auth->shouldReceive('byId')->once()->with(1)->andReturn(true);
        $this->auth->shouldReceive('user')->once()->andReturn((object) ['id' => 1]);

        $user = $this->jwtAuth->setToken('foo.bar.baz')->customClaims(['foo' => 'bar'])->authenticate();

        $this->assertSame($user->id, 1);
    }

    /** @test */
    public function it_should_return_false_when_passing_a_token_not_containing_an_existing_user()
    {
        $payload = Mockery::mock(Payload::class);
        $payload->shouldReceive('get')->once()->with('sub')->andReturn(1);

        $this->manager->shouldReceive('decode')->once()->andReturn($payload);

        $this->auth->shouldReceive('byId')->once()->with(1)->andReturn(false);
        $this->auth->shouldReceive('user')->never();

        $user = $this->jwtAuth->setToken('foo.bar.baz')->authenticate();

        $this->assertFalse($user);
    }

    /** @test */
    public function it_should_refresh_a_token()
    {
        $newToken = Mockery::mock(Token::class);
        $newToken->shouldReceive('get')->once()->andReturn('baz.bar.foo');

        $this->manager->shouldReceive('customClaims->refresh')->once()->andReturn($newToken);

        $result = $this->jwtAuth->setToken('foo.bar.baz')->refresh();

        $this->assertSame($result, 'baz.bar.foo');
    }

    /** @test */
    public function it_should_invalidate_a_token()
    {
        $token = new Token('foo.bar.baz');

        $this->manager->shouldReceive('invalidate')->once()->with($token, false)->andReturn(true);

        $result = $this->jwtAuth->setToken($token)->invalidate();

        $this->assertTrue($result);
    }

    /** @test */
    public function it_should_force_invalidate_a_token_forever()
    {
        $token = new Token('foo.bar.baz');

        $this->manager->shouldReceive('invalidate')->once()->with($token, true)->andReturn(true);

        $result = $this->jwtAuth->setToken($token)->invalidate(true);

        $this->assertTrue($result);
    }

    /** @test */
    public function it_should_retrieve_the_token_from_the_request()
    {
        $this->parser->shouldReceive('parseToken')->andReturn('foo.bar.baz');

        $this->assertInstanceOf(Token::class, $this->jwtAuth->parseToken()->getToken());
        $this->assertEquals($this->jwtAuth->getToken(), 'foo.bar.baz');
    }

    /** @test */
    public function it_should_get_the_authenticated_user()
    {
        $manager = $this->jwtAuth->manager();
        $this->assertInstanceOf(Manager::class, $manager);
    }

    /** @test */
    public function it_should_return_false_if_the_token_is_invalid()
    {
        $this->parser->shouldReceive('parseToken')->andReturn('foo.bar.baz');
        $this->manager->shouldReceive('decode')->once()->andThrow(new TokenInvalidException);

        $this->assertFalse($this->jwtAuth->parseToken()->check());
    }

    /** @test */
    public function it_should_return_true_if_the_token_is_valid()
    {
        $payload = Mockery::mock(Payload::class);

        $this->parser->shouldReceive('parseToken')->andReturn('foo.bar.baz');
        $this->manager->shouldReceive('decode')->once()->andReturn($payload);

        $this->assertTrue($this->jwtAuth->parseToken()->check());
    }

    /**
     * @test
     * @expectedException \JWTAuth\Exceptions\JWTException
     */
    public function it_should_throw_an_exception_when_token_not_present_in_request()
    {
        $this->parser->shouldReceive('parseToken')->andReturn(false);

        $this->jwtAuth->parseToken();
    }

    /** @test */
    public function it_should_return_false_when_no_token_is_set()
    {
        $this->parser->shouldReceive('parseToken')->andReturn(false);

        $this->assertFalse($this->jwtAuth->getToken());
    }

    /** @test */
    public function it_should_magically_call_the_manager()
    {
        $this->manager->shouldReceive('getBlacklist')->andReturn(new StdClass);

        $blacklist = $this->jwtAuth->getBlacklist();

        $this->assertInstanceOf(StdClass::class, $blacklist);
    }

    /** @test */
    public function it_should_set_the_request()
    {
        $request = Request::create('/foo', 'GET', ['token' => 'some.random.token']);

        $this->parser->shouldReceive('setRequest')->once()->with($request);
        $this->parser->shouldReceive('parseToken')->andReturn('some.random.token');

        $token = $this->jwtAuth->setRequest($request)->getToken();

        $this->assertEquals('some.random.token', $token);
    }

    /** @test */
    public function it_should_unset_the_token()
    {
        $this->parser->shouldReceive('parseToken')->andThrow(new JWTException);
        $token = new Token('foo.bar.baz');
        $this->jwtAuth->setToken($token);

        $this->assertSame($this->jwtAuth->getToken(), $token);
        $this->jwtAuth->unsetToken();
        $this->assertFalse($this->jwtAuth->getToken());
    }

    /** @test */
    public function it_should_get_the_manager_instance()
    {
        $manager = $this->jwtAuth->manager();
        $this->assertInstanceOf(Manager::class, $manager);
    }

    /** @test */
    public function it_should_get_the_parser_instance()
    {
        $parser = $this->jwtAuth->parser();
        $this->assertInstanceOf(Parser::class, $parser);
    }
}
