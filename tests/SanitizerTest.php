<?php
require 'data/TestAllowedTags.php';
require 'data/TestAllowedAttributes.php';

use \enshrined\svgSanitize\Sanitizer;
use PHPUnit\Framework\TestCase;

/**
 * Class SanitizerTest
 */
class SanitizerTest extends TestCase
{
    /**
     * @var Sanitizer
     */
    protected $class;

    /**
     * Set up the test class
     */
    public function setUp()
    {
        $this->class = new Sanitizer();
    }

    /**
     * Make sure the initial tags are loaded
     */
    public function testLoadDefaultTags()
    {
        $tags = $this->class->getAllowedTags();

        $this->assertInternalType('array', $tags);
    }

    /**
     * Make sure the initial attributes are loaded
     */
    public function testLoadDefaultAttributes()
    {
        $attributes = $this->class->getAllowedAttrs();

        $this->assertInternalType('array', $attributes);
    }

    /**
     * Test the custom tag setters and getters
     */
    public function testSetCustomTags()
    {
        $this->class->setAllowedTags(new TestAllowedTags());

        $tags = $this->class->getAllowedTags();

        $this->assertInternalType('array', $tags);

        $this->assertEquals(array_map('strtolower', TestAllowedTags::getTags()), $tags);
    }

    /**
     * Test the custom attribute setters and getters
     */
    public function testSetCustomAttributes()
    {
        $this->class->setAllowedAttrs(new TestAllowedAttributes());

        $attributes = $this->class->getAllowedAttrs();

        $this->assertInternalType('array', $attributes);

        $this->assertEquals( array_map('strtolower', TestAllowedAttributes::getAttributes()), $attributes);
    }

    /**
     * Test that malicious elements and attributes are removed from standard XML
     */
    public function testSanitizeXMLDoc()
    {
        $initialData = file_get_contents('tests/data/xmlTestOne.xml');
        $expected = file_get_contents('tests/data/xmlCleanOne.xml');

        $cleanData = $this->class->sanitize($initialData);

        $this->assertXmlStringEqualsXmlString($expected, $cleanData);
    }

    /**
     * Test that malicious elements and attributes are removed from an SVG
     */
    public function testSanitizeSVGDoc()
    {
        $initialData = file_get_contents('tests/data/svgTestOne.svg');
        $expected = file_get_contents('tests/data/svgCleanOne.svg');

        $cleanData = $this->class->sanitize($initialData);

        $this->assertXmlStringEqualsXmlString($expected, $cleanData);
    }

    /**
     * Test that a badly formatted XML document returns false
     */
    public function testBadXMLReturnsFalse()
    {
        $initialData = file_get_contents('tests/data/badXmlTestOne.svg');

        $cleanData = $this->class->sanitize($initialData);

        $this->assertEquals(false, $cleanData);
    }

    /**
     * Make sure that hrefs get sanitized correctly
     */
    public function testSanitizeHrefs()
    {
        $initialData = file_get_contents('tests/data/hrefTestOne.svg');
        $expected = file_get_contents('tests/data/hrefCleanOne.svg');

        $cleanData = $this->class->sanitize($initialData);

        $this->assertXmlStringEqualsXmlString($expected, $cleanData);
    }

    /**
     * Make sure that external references get sanitized correctly
     */
    public function testSanitizeExternal()
    {
        $initialData = file_get_contents('tests/data/externalTest.svg');
        $expected = file_get_contents('tests/data/externalClean.svg');

        $this->class->removeRemoteReferences(true);
        $cleanData = $this->class->sanitize($initialData);
        $this->class->removeRemoteReferences(false);

        $this->assertXmlStringEqualsXmlString($expected, $cleanData);
    }

    /**
     * Test that minification of an SVG works
     */
    public function testSanitizeAndMinifiySVGDoc()
    {
        $initialData = file_get_contents('tests/data/svgTestOne.svg');
        $expected = file_get_contents('tests/data/svgCleanOneMinified.svg');

        $this->class->minify(true);
        $cleanData = $this->class->sanitize($initialData);
        $this->class->minify(false);

        $this->assertXmlStringEqualsXmlString($expected, $cleanData);
    }

    /**
     * Test that ARIA and Data Attributes are allowed
     */
    public function testThatAriaAndDataAttributesAreAllowed()
    {
        $initialData = file_get_contents('tests/data/ariaDataTest.svg');
        $expected = file_get_contents('tests/data/ariaDataClean.svg');

        $this->class->minify(false);
        $cleanData = $this->class->sanitize($initialData);
        $this->class->minify(false);

        $this->assertXmlStringEqualsXmlString($expected, $cleanData);
    }

    /**
     * Test that ARIA and Data Attributes are allowed
     */
    public function testThatExternalUseElementsAreStripped()
    {
        $initialData = file_get_contents('tests/data/useTest.svg');
        $expected = file_get_contents('tests/data/useClean.svg');

        $this->class->minify(false);
        $cleanData = $this->class->sanitize($initialData);
        $this->class->minify(false);

        $this->assertXmlStringEqualsXmlString($expected, $cleanData);
    }

    /**
     * Test setXMLOptions and minifying works as expected
     */
    public function testMinifiedOptions()
    {
        $this->class->minify(true);
        $this->class->removeXMLTag(true);
        $this->class->setXMLOptions(0);

        $input = '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24"><title>chevron-double-down</title><path d="M4 11.73l.68-.73L12 17.82 19.32 11l.68.73-7.66 7.13a.5.5 0 0 1-.68 0z"/><path d="M4 5.73L4.68 5 12 11.82 19.32 5l.68.73-7.66 7.13a.5.5 0 0 1-.68 0z"/></svg>';
        $output = $this->class->sanitize($input);
        $this->assertEquals($input, $output);
    }
}
