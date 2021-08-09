<?php
namespace enshrined\svgSanitize\Tests;

use enshrined\svgSanitize\data\AllowedAttributes;
use PHPUnit\Framework\TestCase;

/**
 * Class AllowedAttributesTest
 */
class AllowedAttributesTest extends TestCase
{
    /**
     * Test that the class implements the interface
     */
    public function testItImplementsTheInterface()
    {
        $class = new AllowedAttributes();
        self::assertInstanceOf('enshrined\svgSanitize\data\AttributeInterface', $class);
    }

    /**
     * Test that an array is returned
     */
    public function testThatItReturnsAnArray()
    {
        $result = AllowedAttributes::getAttributes();
        self::assertSame('array', gettype($result));
    }
}
