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
    public function test_parse_remove_bearer_only_at_the_beginning_of_the_value($value)
    {
        // Arrange
        $header = [ 'Authorization' => [ 'bearer' . $value] ];
        $request = new Request();
        $request->headers->replace($header);
        $authHeaders = new AuthHeaders();

        // Act
        $actual = $authHeaders->parse($request);

        // Assert
        $this->assertEquals($value, $actual);
    }

    public function test_parse_trim_whitespaces()
    {
        // Arrange
        $header = [ 'Authorization' => [ 'bearer' . ' ' . 'one.two.three' . ' '] ];
        $request = new Request();
        $request->headers->replace($header);

        $authHeaders = new AuthHeaders();
        // Act
        $actual = $authHeaders->parse($request);
        
        // Assert
        $this->assertEquals('one.two.three', $actual);
    }

    /**
     * @dataProvider header_value_dataProvider
     */
    public function test_parse_bearer_is_missing_should_return_null($value)
    {
        // Arrange
        $header = [ 'Authorization' => [ $value ] ];
        $request = new Request();
        $request->headers->replace($header);
        $authHeaders = new AuthHeaders();

        // Act
        $actual = $authHeaders->parse($request);

        // Assert
        $this->assertNull($actual);
    }

    /**
     * @dataProvider bearer_case_dataProvider
     */
    public function test_parse_remove_bearer_in_any_type_of_cases($value)
    {
        // Arrange
        $header = [ 'Authorization' => [ $value . ' one.two.three' ] ];
        $request = new Request();
        $request->headers->replace($header);
        $authHeaders = new AuthHeaders();

        // Act
        $actual = $authHeaders->parse($request);

        // Assert
        $this->assertEquals('one.two.three', $actual);
    }

    /**
     * @return string[]
     */
    public function header_value_dataProvider()
    {
        return [
            ['onebearer.two.three'],
            ['one.bearertwo.three'],
            ['one.two.bearerthree'],
        ];
    }

    /**
     * @return string[]
     */
    public function bearer_case_dataProvider()
    {
        return[
            ['bearer'],
            ['BEARER'],
            ['Bearer'],
            ['beareR'],
            ['BeArEr'],
            ['bEaReR']
        ];
    }

}
