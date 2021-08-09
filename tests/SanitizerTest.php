<?php
namespace enshrined\svgSanitize\Tests;

use enshrined\svgSanitize\Sanitizer;
use enshrined\svgSanitize\Tests\Fixtures\TestAllowedAttributes;
use enshrined\svgSanitize\Tests\Fixtures\TestAllowedTags;
use PHPUnit\Framework\TestCase;

/**
 * Class SanitizerTest
 */
class SanitizerTest extends TestCase
{
    /**
     * Make sure the initial tags are loaded
     */
    public function testLoadDefaultTags()
    {
        $sanitizer = new Sanitizer();
        $tags = $sanitizer->getAllowedTags();

        self::assertSame('array', gettype($tags));
    }

    /**
     * Make sure the initial attributes are loaded
     */
    public function testLoadDefaultAttributes()
    {
        $sanitizer = new Sanitizer();
        $attributes = $sanitizer->getAllowedAttrs();

        self::assertSame('array', gettype($attributes));
    }

    /**
     * Test the custom tag setters and getters
     */
    public function testSetCustomTags()
    {
        $sanitizer = new Sanitizer();
        $sanitizer->setAllowedTags(new TestAllowedTags());
        $tags = $sanitizer->getAllowedTags();

        self::assertSame('array', gettype($tags));
        self::assertSame(array_map('strtolower', TestAllowedTags::getTags()), $tags);
    }

    /**
     * Test the custom attribute setters and getters
     */
    public function testSetCustomAttributes()
    {
        $sanitizer = new Sanitizer();
        $sanitizer->setAllowedAttrs(new TestAllowedAttributes());
        $attributes = $sanitizer->getAllowedAttrs();

        self::assertSame('array', gettype($attributes));
        self::assertSame( array_map('strtolower', TestAllowedAttributes::getAttributes()), $attributes);
    }

    /**
     * Test that malicious elements and attributes are removed from standard XML
     */
    public function testSanitizeXMLDoc()
    {
        $dataDirectory = __DIR__ . '/data';
        $initialData = file_get_contents($dataDirectory . '/xmlTestOne.xml');
        $expected = file_get_contents($dataDirectory . '/xmlCleanOne.xml');

        $sanitizer = new Sanitizer();
        $cleanData = $sanitizer->sanitize($initialData);

        self::assertXmlStringEqualsXmlString($expected, $cleanData);
    }

    /**
     * Test that malicious elements and attributes are removed from an SVG
     */
    public function testSanitizeSVGDoc()
    {
        $dataDirectory = __DIR__ . '/data';
        $initialData = file_get_contents($dataDirectory . '/svgTestOne.svg');
        $expected = file_get_contents($dataDirectory . '/svgCleanOne.svg');

        $sanitizer = new Sanitizer();
        $cleanData = $sanitizer->sanitize($initialData);

        self::assertXmlStringEqualsXmlString($expected, $cleanData);
    }

    /**
     * Test that a badly formatted XML document returns false
     */
    public function testBadXMLReturnsFalse()
    {
        $dataDirectory = __DIR__ . '/data';
        $initialData = file_get_contents($dataDirectory . '/badXmlTestOne.svg');

        $sanitizer = new Sanitizer();
        $cleanData = $sanitizer->sanitize($initialData);

        self::assertSame(false, $cleanData);
    }

    /**
     * Make sure that hrefs get sanitized correctly
     */
    public function testSanitizeHrefs()
    {
        $dataDirectory = __DIR__ . '/data';
        $initialData = file_get_contents($dataDirectory . '/hrefTestOne.svg');
        $expected = file_get_contents($dataDirectory . '/hrefCleanOne.svg');

        $sanitizer = new Sanitizer();
        $cleanData = $sanitizer->sanitize($initialData);

        self::assertXmlStringEqualsXmlString($expected, $cleanData);
    }

    /**
     * Make sure that hrefs get sanitized correctly when the xlink namespace is omitted.
     */
    public function testSanitizeHrefsNoXlinkNamespace()
    {
        $dataDirectory = __DIR__ . '/data';
        $initialData = file_get_contents($dataDirectory . '/hrefTestTwo.svg');
        $expected = file_get_contents($dataDirectory . '/hrefCleanTwo.svg');

        $sanitizer = new Sanitizer();
        $cleanData = $sanitizer->sanitize($initialData);

        self::assertXmlStringEqualsXmlString($expected, $cleanData);
    }

    /**
     * Make sure that external references get sanitized correctly
     */
    public function testSanitizeExternal()
    {
        $dataDirectory = __DIR__ . '/data';
        $initialData = file_get_contents($dataDirectory . '/externalTest.svg');
        $expected = file_get_contents($dataDirectory . '/externalClean.svg');

        $sanitizer = new Sanitizer();
        $sanitizer->removeRemoteReferences(true);
        $cleanData = $sanitizer->sanitize($initialData);

        self::assertXmlStringEqualsXmlString($expected, $cleanData);
    }

    /**
     * Test that minification of an SVG works
     */
    public function testSanitizeAndMinifiySVGDoc()
    {
        $dataDirectory = __DIR__ . '/data';
        $initialData = file_get_contents($dataDirectory . '/svgTestOne.svg');
        $expected = file_get_contents($dataDirectory . '/svgCleanOneMinified.svg');

        $sanitizer = new Sanitizer();
        $sanitizer->minify(true);
        $cleanData = $sanitizer->sanitize($initialData);

        self::assertXmlStringEqualsXmlString($expected, $cleanData);
    }

    /**
     * Test that ARIA and Data Attributes are allowed
     */
    public function testThatAriaAndDataAttributesAreAllowed()
    {
        $dataDirectory = __DIR__ . '/data';
        $initialData = file_get_contents($dataDirectory . '/ariaDataTest.svg');
        $expected = file_get_contents($dataDirectory . '/ariaDataClean.svg');

        $sanitizer = new Sanitizer();
        $sanitizer->minify(false);
        $cleanData = $sanitizer->sanitize($initialData);

        self::assertXmlStringEqualsXmlString($expected, $cleanData);
    }

    /**
     * Test that ARIA and Data Attributes are allowed
     */
    public function testThatExternalUseElementsAreStripped()
    {
        $dataDirectory = __DIR__ . '/data';
        $initialData = file_get_contents($dataDirectory . '/useTest.svg');
        $expected = file_get_contents($dataDirectory . '/useClean.svg');

        $sanitizer = new Sanitizer();
        $sanitizer->minify(false);
        $cleanData = $sanitizer->sanitize($initialData);

        self::assertXmlStringEqualsXmlString($expected, $cleanData);
    }

    /**
     * Test setXMLOptions and minifying works as expected
     */
    public function testMinifiedOptions()
    {
        $sanitizer = new Sanitizer();
        $sanitizer->minify(true);
        $sanitizer->removeXMLTag(true);
        $sanitizer->setXMLOptions(0);

        $input = '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24"><title>chevron-double-down</title><path d="M4 11.73l.68-.73L12 17.82 19.32 11l.68.73-7.66 7.13a.5.5 0 0 1-.68 0z"/><path d="M4 5.73L4.68 5 12 11.82 19.32 5l.68.73-7.66 7.13a.5.5 0 0 1-.68 0z"/></svg>';
        $output = $sanitizer->sanitize($input);

        self::assertSame($input, $output);
    }

    /**
     * @test
     */
    public function useRecursionsAreDetected()
    {
        $dataDirectory = __DIR__ . '/data';
        $initialData = file_get_contents($dataDirectory . '/xlinkLaughsTest.svg');
        $expected = file_get_contents($dataDirectory . '/xlinkLaughsClean.svg');

        $sanitizer = new Sanitizer();
        $sanitizer->minify(false);
        $cleanData = $sanitizer->sanitize($initialData);

        self::assertXmlStringEqualsXmlString($expected, $cleanData);
    }

    /**
     * @test
     */
    public function infiniteUseLoopsAreDetected()
    {
        $dataDirectory = __DIR__ . '/data';
        $initialData = file_get_contents($dataDirectory . '/xlinkLoopTest.svg');
        $expected = file_get_contents($dataDirectory . '/xlinkLoopClean.svg');

        $sanitizer = new Sanitizer();
        $sanitizer->minify(false);
        $cleanData = $sanitizer->sanitize($initialData);

        self::assertXmlStringEqualsXmlString($expected, $cleanData);
    }

    /**
     * @test
     */
    public function doctypeAndEntityAreRemoved()
    {
        $dataDirectory = __DIR__ . '/data';
        $initialData = file_get_contents($dataDirectory . '/entityTest.svg');
        $expected = file_get_contents($dataDirectory . '/entityClean.svg');

	    $sanitizer = new Sanitizer();
	    $sanitizer->minify(false);
	    $sanitizer->removeRemoteReferences(true);
	    $cleanData = $sanitizer->sanitize($initialData);

        self::assertSame($expected, $cleanData);
    }

    /**
     * Make sure that DOS attacks using the <use> element are detected.
     */
    public function testUseDOSattacksAreNullified()
    {
        $dataDirectory = __DIR__ . '/data';
        $initialData = file_get_contents($dataDirectory . '/useDosTest.svg');
        $expected = file_get_contents($dataDirectory . '/useDosClean.svg');

        $sanitizer = new Sanitizer();
        $sanitizer->minify(false);
        $cleanData = $sanitizer->sanitize($initialData);

        self::assertXmlStringEqualsXmlString($expected, $cleanData);
    }

    /**
     * Make sure that DOS attacks using the <use> element are detected,
     * especially when the SVG is extremely large.
     */
    public function testLargeUseDOSattacksAreNullified()
    {
        $dataDirectory = __DIR__ . '/data';
        $initialData = file_get_contents($dataDirectory . '/useDosTestTwo.svg');
        $expected = file_get_contents($dataDirectory . '/useDosCleanTwo.svg');

        $sanitizer = new Sanitizer();
        $sanitizer->minify(false);
        $cleanData = $sanitizer->sanitize($initialData);

        self::assertXmlStringEqualsXmlString($expected, $cleanData);
    }
}
