<?php
require 'data/TestAllowedTags.php';
require 'data/TestAllowedAttributes.php';

use enshrined\svgSanitize\data\AllowedAttributes;
use \enshrined\svgSanitize\Sanitizer;

/**
 * Class SanitizerTest
 */
class SanitizerTest extends PHPUnit_Framework_TestCase
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
        $this->assertEquals(TestAllowedTags::getTags(), $tags);
    }

    /**
     * Test the custom attribute setters and getters
     */
    public function testSetCustomAttributes()
    {
        $this->class->setAllowedAttrs(new TestAllowedAttributes());

        $attributes = $this->class->getAllowedAttrs();

        $this->assertInternalType('array', $attributes);
        $this->assertEquals(TestAllowedAttributes::getAttributes(), $attributes);
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
     * Test to demonstrate the case sensitivity issue described here https://github.com/darylldoyle/svg-sanitizer/issues/3
     * This test will fail, because the viewBox attribute won't get replaced anymore
     * The original version of allowed attributes only adds "viewbox" to the whitelist
     */
    public function testAllowedAttributesShouldConsiderCaseSensitivity()
    {
        $this->class->setAllowedAttrs(new LowerCamelCaseAllowedAttributes());

        $initialData = file_get_contents('tests/data/svgTestOne.svg');
        $expected = file_get_contents('tests/data/svgCleanOne.svg');

        $cleanData = $this->class->sanitize($initialData);

        $this->assertXmlStringEqualsXmlString($expected, $cleanData);
    }

}

class LowerCamelCaseAllowedAttributes extends AllowedAttributes
{
    /**
     * @var array
     * @see https://developer.mozilla.org/de/docs/Web/SVG/Attribute
     */
    private static $lowerCamelCaseAttributes = [
        "allowReorder",
        "attributeName",
        "attributeType",
        "autoReverse",
        "baseFrequency",
        "baseProfile",
        "calcMode",
        "clipPathUnits",
        "contentScriptType",
        "contentStyleType",
        "diffuseConstant",
        "edgeMode",
        "externalResourcesRequired",
        "filterRes",
        "filterUnits",
        "glyphRef",
        "gradientTransform",
        "gradientUnits",
        "kernelMatrix",
        "kernelUnitLength",
        "keyPoints",
        "keySplines",
        "keyTimes",
        "lengthAdjust",
        "limitingConeAngle",
        "markerHeight",
        "markerUnits",
        "markerWidth",
        "maskContentUnits",
        "maskUnits",
        "numOctaves",
        "pathLength",
        "patternContentUnits",
        "patternTransform",
        "patternUnits",
        "pointsAtX",
        "pointsAtY",
        "pointsAtZ",
        "preserveAlpha",
        "preserveAspectRatio",
        "primitiveUnits",
        "refX",
        "refY",
        "repeatCount",
        "repeatDur",
        "requiredExtensions",
        "requiredFeatures",
        "specularConstant",
        "specularExponent",
        "spreadMethod",
        "startOffset",
        "stdDeviation",
        "stitchTiles",
        "surfaceScale",
        "systemLanguage",
        "tableValues",
        "targetX",
        "targetY",
        "textLength",
        "viewBox",
        "viewTarget",
        "xChannelSelector",
        "yChannelSelector",
        "zoomAndPan",
    ];

    /**
     * @inheritdoc
     */
    public static function getAttributes()
    {
        return array_merge(parent::getAttributes(), static::$lowerCamelCaseAttributes);
    }

}
