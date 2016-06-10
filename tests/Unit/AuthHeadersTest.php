<?php
/**
 * Created by PhpStorm.
 * User: gajdacsn
 * Date: 2016. 06. 10.
 * Time: 8:35.
 */
namespace Tymon\JWTAuth\Test\Unit;

use Symfony\Component\HttpFoundation\Request;
use Tymon\JWTAuth\Http\Parser\AuthHeaders;

class AuthHeadersTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @dataProvider header_value_dataProvider
     */
    public function test_parse_cut_bearer_only_at_the_beginning_of_the_value($value)
    {
        // Arrange
        $request = Request::create('foo', 'POST');
        $request->headers->set('Authorization', 'bearer '.$value);
        $authHeaders = new AuthHeaders();

        // Act
        $actual = $authHeaders->parse($request);

        // Assert
        $this->assertEquals($value, $actual);
    }

    /**
     * @dataProvider header_value_dataProvider
     */
    public function test_parse_bearer_is_missing_should_return_null($value)
    {
        // Arrange
        $request = Request::create('foo', 'POST');
        $request->headers->set('Authorization', $value);
        $authHeaders = new AuthHeaders();

        // Act
        $actual = $authHeaders->parse($request);

        // Assert
        $this->assertNull($actual);
    }

    public function header_value_dataProvider()
    {
        return [
            ['onebearer.two.three'],
            ['one.bearertwo.three'],
            ['one.two.bearerthree'],
        ];
    }
}
