<?php
namespace enshrined\svgSanitize\Tests;

use enshrined\svgSanitize\data\AllowedTags;
use PHPUnit\Framework\TestCase;

/**
 * Class AllowedTagsTest
 */
class AllowedTagsTest extends TestCase
{
    /**
     * Test that the class implements the interface
     */
    public function testItImplementsTheInterface()
    {
        $class = new AllowedTags();
        self::assertInstanceOf('enshrined\svgSanitize\data\TagInterface', $class);
    }

    /**
     * Test that an array is returned
     */
    public function testThatItReturnsAnArray()
    {
        $result = AllowedTags::getTags();
        self::assertSame('array', gettype($result));
    }
}
