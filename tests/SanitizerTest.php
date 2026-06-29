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

        self::assertFalse($cleanData);
        self::assertEquals(
            [
                [
                    'message' => 'Opening and ending tag mismatch: line line 8 and svg',
                    'line' => 15,
                ],
                [
                    'message' => 'Premature end of data in tag svg line 4',
                    'line' => 16,
                ],
            ],
            $sanitizer->getXmlIssues()
        );
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
     * The DTD is now stripped before parsing, so a document that references a custom
     * entity ends up referencing an *undefined* entity. libxml rejects it and the
     * sanitizer returns false (fail-safe) rather than a cleaned string.
     *
     * @test
     */
    public function doctypeAndEntityAreRemoved()
    {
        $dataDirectory = __DIR__ . '/data';
        $initialData = file_get_contents($dataDirectory . '/entityTest.svg');

        $sanitizer = new Sanitizer();
        $sanitizer->minify(false);
        $sanitizer->removeRemoteReferences(true);
        $cleanData = $sanitizer->sanitize($initialData);

        self::assertFalse($cleanData);

        // Rejected for the right reason: the custom entity is no longer defined.
        $rejectedForUndefinedEntity = false;
        foreach ($sanitizer->getXmlIssues() as $issue) {
            if (stripos($issue['message'], 'not defined') !== false) {
                $rejectedForUndefinedEntity = true;
                break;
            }
        }
        self::assertTrue($rejectedForUndefinedEntity, 'Expected an undefined-entity parse error');
    }

    /**
     * A PUBLIC DOCTYPE with no entity definitions (typical Illustrator/Inkscape export)
     * must still sanitize normally after the DTD is stripped.
     *
     * @test
     */
    public function publicDoctypeWithoutEntitiesStillSanitizes()
    {
        $svg = "<?xml version=\"1.0\"?>\n"
            . "<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" \"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd\">\n"
            . "<svg xmlns=\"http://www.w3.org/2000/svg\"><rect width=\"10\" height=\"10\"/></svg>";

        $sanitizer = new Sanitizer();
        $clean = $sanitizer->sanitize($svg);

        self::assertTrue(is_string($clean));
        self::assertTrue(false !== strpos($clean, '<svg'), 'svg root should survive');
        self::assertTrue(false !== strpos($clean, '<rect'), 'rect should survive');
        self::assertTrue(false === stripos($clean, '<!DOCTYPE'), 'DOCTYPE should be stripped');
    }

    /**
     * Issue 1 (GHSA-9rjx-3jch-6vjf): a custom DTD entity that collides with an HTML5
     * named character reference (e.g. &Tab; => U+0009) must not be able to smuggle a
     * javascript: URL through an href. Stripping the DTD makes the entity undefined,
     * so the document is rejected outright.
     *
     * @test
     */
    public function entityHrefBypassIsRejected()
    {
        $dataDirectory = __DIR__ . '/data';
        $initialData = file_get_contents($dataDirectory . '/entityHrefBypassTest.svg');

        $sanitizer = new Sanitizer();
        $cleanData = $sanitizer->sanitize($initialData);

        // Undefined entity after DTD removal -> libxml rejects -> false.
        self::assertFalse($cleanData);
    }

    /**
     * Issue 2 (GHSA-v383-3rw5-q8rf): a DTD #FIXED attribute default used to trigger a
     * double removeAttribute() on a DTD-materialised attribute, corrupting libxml
     * memory (SIGABRT on libxml < 2.9.x). After DTD stripping the attribute never
     * materialises, so there is nothing to double-remove.
     *
     * NOTE: the crash only reproduces on older libxml; on newer libxml this passes
     * even without the fix, so it serves as a regression guard rather than a
     * red->green test on modern environments.
     *
     * @test
     */
    public function attlistFixedDefaultDoesNotCrashAndIsRemoved()
    {
        $dataDirectory = __DIR__ . '/data';
        $initialData = file_get_contents($dataDirectory . '/attlistFixedDosTest.svg');

        $sanitizer = new Sanitizer();
        $cleanData = $sanitizer->sanitize($initialData);

        self::assertTrue(is_string($cleanData), 'valid body should still sanitize to a string');
        self::assertTrue(false === stripos($cleanData, 'badhref'), 'DTD-defaulted attribute must be gone');
        self::assertTrue(false === strpos($cleanData, 'javascript:'), 'payload must not survive');
    }

    /**
     * Issue 3 (Report 2.2): a bare remote href must be stripped under
     * removeRemoteReferences(true).
     *
     * @test
     */
    public function removeRemoteReferencesStripsBareRemoteImageHref()
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">'
            . '<image href="https://evil.com/x.png"/></svg>';

        $sanitizer = new Sanitizer();
        $sanitizer->removeRemoteReferences(true);
        $clean = $sanitizer->sanitize($svg);

        self::assertTrue(is_string($clean));
        self::assertTrue(false === strpos($clean, 'evil.com'), 'remote image href should be removed');
    }

    /**
     * Issue 3 (Report 2.3): an unquoted url() remote reference must be stripped.
     *
     * @test
     */
    public function removeRemoteReferencesStripsUnquotedRemoteUrl()
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg">'
            . '<rect fill="url(https://evil.com/x)" width="1" height="1"/></svg>';

        $sanitizer = new Sanitizer();
        $sanitizer->removeRemoteReferences(true);
        $clean = $sanitizer->sanitize($svg);

        self::assertTrue(is_string($clean));
        self::assertTrue(false === strpos($clean, 'evil.com'), 'unquoted remote url() should be removed');
    }

    /**
     * Issue 3 (#116): a remote url() embedded among other declarations inside a style
     * attribute must be stripped.
     *
     * @test
     */
    public function removeRemoteReferencesStripsRemoteUrlInStyleAttribute()
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg">'
            . '<rect style="fill:url(https://evil.com/x);stroke:red" width="1" height="1"/></svg>';

        $sanitizer = new Sanitizer();
        $sanitizer->removeRemoteReferences(true);
        $clean = $sanitizer->sanitize($svg);

        self::assertTrue(is_string($clean));
        self::assertTrue(false === strpos($clean, 'evil.com'), 'remote url() in style attribute should be removed');
    }

    /**
     * Issue 3: remote @import / url() inside a <style> element must be stripped, while
     * legitimate local CSS rules are preserved.
     *
     * @test
     */
    public function removeRemoteReferencesStripsRemoteCssInStyleElement()
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg">'
            . '<style>@import url(https://evil.com/x.css); .a{fill:red}</style>'
            . '<rect width="1" height="1"/></svg>';

        $sanitizer = new Sanitizer();
        $sanitizer->removeRemoteReferences(true);
        $clean = $sanitizer->sanitize($svg);

        self::assertTrue(is_string($clean));
        self::assertTrue(false === strpos($clean, 'evil.com'), 'remote @import should be removed');
        self::assertTrue(false !== strpos($clean, 'fill:red'), 'legitimate local CSS should be preserved');
    }

    /**
     * Regression guard: local fragment references must be preserved under
     * removeRemoteReferences(true).
     *
     * @test
     */
    public function removeRemoteReferencesKeepsLocalFragmentUrl()
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg">'
            . '<rect fill="url(#grad)" width="1" height="1"/></svg>';

        $sanitizer = new Sanitizer();
        $sanitizer->removeRemoteReferences(true);
        $clean = $sanitizer->sanitize($svg);

        self::assertTrue(is_string($clean));
        self::assertTrue(false !== strpos($clean, '#grad'), 'local fragment reference should be kept');
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

    public function testInvalidNodesAreHandled()
    {
        $dataDirectory = __DIR__ . '/data';
        $initialData = file_get_contents($dataDirectory . '/htmlTest.svg');
        $expected = file_get_contents($dataDirectory . '/htmlClean.svg');

        $sanitizer = new Sanitizer();
        $sanitizer->minify(false);
        $cleanData = $sanitizer->sanitize($initialData);

        self::assertXmlStringEqualsXmlString($expected, $cleanData);
    }

    /**
     * @test
     */
    public function cdataSectionIsSanitized()
    {
        $dataDirectory = __DIR__ . '/data';
        $initialData = file_get_contents($dataDirectory . '/cdataTest.svg');
        $expected = file_get_contents($dataDirectory . '/cdataClean.svg');

        $sanitizer = new Sanitizer();
        $sanitizer->minify(false);
        $cleanData = $sanitizer->sanitize($initialData);

        self::assertXmlStringEqualsXmlString($expected, $cleanData);
    }

    /**
     * @test
     */
    public function cdataBackgroundSectionIsSanitized()
    {
        $dataDirectory = __DIR__ . '/data';
        $initialData = file_get_contents($dataDirectory . '/cdataTwoTest.svg');
        $expected = file_get_contents($dataDirectory . '/cdataTwoClean.svg');

        $sanitizer = new Sanitizer();
        $sanitizer->minify(false);
        $cleanData = $sanitizer->sanitize($initialData);

        self::assertXmlStringEqualsXmlString($expected, $cleanData);
    }

    /**
     * @test
     */
    public function formDataisSanitized()
    {
        $dataDirectory = __DIR__ . '/data';
        $initialData = file_get_contents($dataDirectory . '/formDataTest.svg');
        $expected = file_get_contents($dataDirectory . '/formDataClean.svg');

        $sanitizer = new Sanitizer();
        $sanitizer->minify(false);
        $cleanData = $sanitizer->sanitize($initialData);

        self::assertXmlStringEqualsXmlString($expected, $cleanData);
    }

    /**
     * @test
     */
    public function maliciousSvgJsSanitized()
    {
        $dataDirectory = __DIR__ . '/data';
        $initialData = file_get_contents($dataDirectory . '/maliciousJsAndPhpTest.svg');
        $expected = file_get_contents($dataDirectory . '/maliciousJsAndPhpClean.svg');


        $sanitizer = new Sanitizer();
        $sanitizer->minify(false);
        $cleanData = $sanitizer->sanitize($initialData);

        self::assertXmlStringEqualsXmlString($expected, $cleanData);
    }

    /**
     * @test
     */
    public function maliciousSvgPhpTagsStripped()
    {
        $dataDirectory = __DIR__ . '/data';
        $initialData = file_get_contents($dataDirectory . '/maliciousJsAndPhpTest.svg');

        $sanitizer = new Sanitizer();
        $sanitizer->minify(false);
        $cleanData = $sanitizer->sanitize($initialData);

        $useNewMethod = true;

        if (!method_exists($this, 'assertStringNotContainsStringIgnoringCase')) {
            $useNewMethod = false;
        }

        foreach (['<?php', '<?='] as $value) {
            if ($useNewMethod) {
                self::assertStringNotContainsStringIgnoringCase($value, $cleanData);
            } else {
                self::assertThat($cleanData, $this->logicalNot($this->stringContains($value, true)));
            }
        }
    }
}
