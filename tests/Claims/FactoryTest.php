<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace JWTAuth\Test\Claims;

use JWTAuth\Claim\JwtId;
use JWTAuth\Claim\Custom;
use JWTAuth\Claim\Issuer;
use JWTAuth\Claim\Factory;
use JWTAuth\Claim\Subject;
use JWTAuth\Claim\IssuedAt;
use JWTAuth\Claim\NotBefore;
use JWTAuth\Claim\Expiration;
use JWTAuth\Test\AbstractTestCase;

class FactoryTest extends AbstractTestCase
{
    /**
     * @var \JWTAuth\Claim\Factory
     */
    protected $factory;

    public function setUp()
    {
        parent::setUp();

        $this->factory = new Factory;
    }

    /** @test */
    public function it_should_get_a_defined_claim_instance_when_passing_a_name_and_value()
    {
        $this->assertInstanceOf(Subject::class, $this->factory->get('sub', 1));
        $this->assertInstanceOf(Issuer::class, $this->factory->get('iss', 'http://example.com'));
        $this->assertInstanceOf(Expiration::class, $this->factory->get('exp', $this->testNowTimestamp + 3600));
        $this->assertInstanceOf(NotBefore::class, $this->factory->get('nbf', $this->testNowTimestamp));
        $this->assertInstanceOf(IssuedAt::class, $this->factory->get('iat', $this->testNowTimestamp));
        $this->assertInstanceOf(JwtId::class, $this->factory->get('jti', 'foo'));
    }

    /** @test */
    public function it_should_get_a_custom_claim_instance_when_passing_a_non_defined_name_and_value()
    {
        $this->assertInstanceOf(Custom::class, $this->factory->get('foo', ['bar']));
    }
}
