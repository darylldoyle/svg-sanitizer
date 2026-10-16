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

        // Malformed XML must be rejected outright.
        self::assertFalse($cleanData);

        // The exact set and wording of libxml parse errors varies by libxml version
        // (newer libxml stops after the first fatal error), so assert that the key
        // error is reported rather than requiring an exact, version-specific list.
        $issues = $sanitizer->getXmlIssues();
        self::assertNotEmpty($issues);

        $reportedTagMismatch = false;
        foreach ($issues as $issue) {
            if (stripos($issue['message'], 'Opening and ending tag mismatch') !== false) {
                $reportedTagMismatch = true;
                break;
            }
        }
        self::assertTrue($reportedTagMismatch, 'Expected a tag-mismatch parse error to be reported');
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

    /**
     * Attribute names that `Sanitizer::cleanHrefAttributes()` normalizes, paired with
     * the canonical name they are normalized to.
     *
     * @return array<string, array{0: string, 1: string}>
     */
    public static function mixedCaseHrefAttributeNameDataProvider()
    {
        return [
            'xlink:HrEf' => ['xlink:HrEf', 'xlink:href'],
            'xlink:HREF' => ['xlink:HREF', 'xlink:href'],
            'href' => ['href', 'href'],
            'HrEf' => ['HrEf', 'href'],
            'HREF' => ['HREF', 'href'],
        ];
    }

    /**
     * The `<use>` reference graph is built before `cleanHrefAttributes()` normalizes
     * names such as `xlink:HrEf` back to `xlink:href`. Selecting the referencing
     * elements case sensitively therefore used to hide the whole nesting bomb from
     * the graph, and the sanitizer handed it back intact with canonical attributes.
     *
     * @test
     * @dataProvider mixedCaseHrefAttributeNameDataProvider
     */
    public function useDOSattacksAreNullifiedForMixedCaseHrefAttributes($attributeName, $canonicalName)
    {
        $dataDirectory = __DIR__ . '/data';
        $initialData = str_replace(
            'xlink:href',
            $attributeName,
            file_get_contents($dataDirectory . '/useDosTest.svg')
        );
        $expected = file_get_contents($dataDirectory . '/useDosClean.svg');

        $sanitizer = new Sanitizer();
        $sanitizer->minify(false);
        $cleanData = $sanitizer->sanitize($initialData);

        // Plain string/regex checks rather than PHPUnit's string constraints: the
        // matrix runs PHPUnit 6.5 on PHP 7.1 and 8.5 everywhere else, and the
        // relevant assertions do not exist across that whole range.
        self::assertSame(0, substr_count($cleanData, '<use'));
        self::assertXmlStringEqualsXmlString($expected, $cleanData);
    }

    /**
     * Same as above for the `useThreshold` machinery, which counts uses on the
     * very same reference graph.
     *
     * @test
     * @dataProvider mixedCaseHrefAttributeNameDataProvider
     */
    public function useRecursionsAreDetectedForMixedCaseHrefAttributes($attributeName, $canonicalName)
    {
        $dataDirectory = __DIR__ . '/data';
        $initialData = str_replace(
            'xlink:href',
            $attributeName,
            file_get_contents($dataDirectory . '/xlinkLaughsTest.svg')
        );
        $expected = str_replace(
            'xlink:href',
            $canonicalName,
            file_get_contents($dataDirectory . '/xlinkLaughsClean.svg')
        );

        $sanitizer = new Sanitizer();
        $sanitizer->minify(false);
        $cleanData = $sanitizer->sanitize($initialData);

        self::assertXmlStringEqualsXmlString($expected, $cleanData);
    }

    /**
     * A mixed-case *prefix* (`XLINK:href`) is not bound to the xlink namespace, so the
     * attribute is dropped wholesale by `cleanXlinkHrefs()`. The `<use>` elements survive
     * as leftovers, but without an href they reference nothing and expand to nothing.
     *
     * @test
     */
    public function useElementsWithUnboundHrefPrefixLoseTheirReference()
    {
        $dataDirectory = __DIR__ . '/data';
        $initialData = str_replace(
            'xlink:href',
            'XLINK:href',
            file_get_contents($dataDirectory . '/useDosTest.svg')
        );

        $sanitizer = new Sanitizer();
        $sanitizer->minify(false);
        $cleanData = $sanitizer->sanitize($initialData);

        self::assertSame(0, preg_match('/<use[^>]*href/i', $cleanData));
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
     * SMIL animation elements can retarget an already-validated `href` at runtime.
     * Safari only requires the animation target to be animatable rather than
     * transform-specific, so `<animateTransform attributeName="href">` can turn a
     * safe link into a `javascript:` URI via `values`/`by`. Any animation whose
     * target is href-like must lose its `attributeName`, while ordinary animations
     * are left alone.
     *
     * @test
     */
    public function animatedHrefIsSanitized()
    {
        $dataDirectory = __DIR__ . '/data';
        $initialData = file_get_contents($dataDirectory . '/animatedHrefTest.svg');
        $expected = file_get_contents($dataDirectory . '/animatedHrefClean.svg');

        $sanitizer = new Sanitizer();
        $sanitizer->minify(false);
        $cleanData = $sanitizer->sanitize($initialData);

        self::assertXmlStringEqualsXmlString($expected, $cleanData);
    }

    /**
     * The animated-href check must not fire on a legitimate animation, and must
     * still fire when the target is obfuscated by case or padding.
     *
     * @test
     */
    public function animatedHrefTargetsAreMatchedLoosely()
    {
        $cases = array(
            'href'        => false,
            'xlink:href'  => false,
            'HrEf'        => false,
            ' href '      => false,
            'XLINK:HREF'  => false,
            'transform'   => true,
            'opacity'     => true,
            'fill'        => true,
        );

        foreach ($cases as $target => $shouldSurvive) {
            $initialData = '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">'
                . '<a href="#safe"><animateTransform attributeName="' . $target . '" type="invalid"'
                . ' values="XXX;javascript:alert(1)//" dur="0.1s" fill="freeze"/></a></svg>';

            $sanitizer = new Sanitizer();
            $cleanData = $sanitizer->sanitize($initialData);

            if ($shouldSurvive) {
                self::assertTrue(
                    false !== strpos($cleanData, 'attributeName="' . $target . '"'),
                    sprintf('legitimate animation of \'%s\' must be preserved', $target)
                );
            } else {
                self::assertTrue(
                    false === strpos($cleanData, 'attributeName'),
                    sprintf('animation targeting \'%s\' must lose its attributeName', $target)
                );
            }
        }
    }

    /**
     * When `href` and `xlink:href` coexist on the same element, both must be
     * processed by the href cleaning pass: iterating the attribute map by key
     * collapses them onto the same `href` key, hiding one of the two.
     *
     * @test
     */
    public function unsafeXlinkHrefIsDetectedWhenPlainHrefCoexists()
    {
        $initialData = '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">'
            . '<a xlink:href="javascript:alert(1)" href="https://example.com/safe">'
            . '<text x="10" y="10">x</text></a></svg>';

        $sanitizer = new Sanitizer();
        $cleanData = $sanitizer->sanitize($initialData);

        self::assertTrue(false === strpos($cleanData, 'javascript:'), 'payload must not survive');
        self::assertContains(
            [
                'message' => 'Suspicious attribute \'xlink:href\'',
                'line' => 1,
            ],
            $sanitizer->getXmlIssues()
        );
    }

    /**
     * @test
     */
    public function mixedCaseHrefIsNormalizedWhenXlinkHrefCoexists()
    {
        $initialData = '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">'
            . '<a HREF="#safe" xlink:HREF="#safeTwo">'
            . '<text x="10" y="10">x</text></a></svg>';

        $expected = '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">'
            . '<a href="#safe" xlink:href="#safeTwo">'
            . '<text x="10" y="10">x</text></a></svg>';

        $sanitizer = new Sanitizer();
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

    /**
     * Issue 3 follow-up: a remote url() hidden behind CSS escapes ("\75 rl(")
     * inside a <style> element must still be stripped.
     *
     * @test
     */
    public function removeRemoteReferencesStripsEscapedRemoteUrlInStyleElement()
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg">'
            . '<style>x{background:\\75 rl(https://evil.com/track)}</style>'
            . '<rect width="1" height="1"/></svg>';

        $sanitizer = new Sanitizer();
        $sanitizer->removeRemoteReferences(true);
        $clean = $sanitizer->sanitize($svg);

        self::assertTrue(is_string($clean));
        self::assertTrue(false === strpos($clean, 'evil.com'), 'escape-obfuscated remote url() should be removed');
    }

    /**
     * Issue 3 follow-up: an escaped @import ("@\69 mport") inside a <style>
     * element must still be stripped.
     *
     * @test
     */
    public function removeRemoteReferencesStripsEscapedRemoteImportInStyleElement()
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg">'
            . '<style>@\\69 mport "https://evil.com/track";</style>'
            . '<rect width="1" height="1"/></svg>';

        $sanitizer = new Sanitizer();
        $sanitizer->removeRemoteReferences(true);
        $clean = $sanitizer->sanitize($svg);

        self::assertTrue(is_string($clean));
        self::assertTrue(false === strpos($clean, 'evil.com'), 'escape-obfuscated @import should be removed');
    }

    /**
     * Issue 3 follow-up: a remote reference hidden behind a CSS comment inside a
     * <style> element must still be stripped.
     *
     * @test
     */
    public function removeRemoteReferencesStripsCommentObfuscatedRemoteImport()
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg">'
            . '<style>@import/* x */url(https://evil.com/track);</style>'
            . '<rect width="1" height="1"/></svg>';

        $sanitizer = new Sanitizer();
        $sanitizer->removeRemoteReferences(true);
        $clean = $sanitizer->sanitize($svg);

        self::assertTrue(is_string($clean));
        self::assertTrue(false === strpos($clean, 'evil.com'), 'comment-obfuscated remote reference should be removed');
    }

    /**
     * Regression: legitimate escaped CSS in a <style> block with no remote
     * reference must be preserved untouched under removeRemoteReferences(true).
     *
     * @test
     */
    public function removeRemoteReferencesPreservesLegitimateEscapedCss()
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg">'
            . '<style>.foo\\:bar{color:red}</style>'
            . '<rect width="1" height="1"/></svg>';

        $sanitizer = new Sanitizer();
        $sanitizer->removeRemoteReferences(true);
        $clean = $sanitizer->sanitize($svg);

        self::assertTrue(is_string($clean));
        self::assertTrue(false !== strpos($clean, 'color:red'), 'legitimate CSS should be preserved');
        self::assertTrue(false !== strpos($clean, 'foo\\:bar'), 'escaped selector should be preserved untouched');
    }

    /**
     * removeDoctype() must fully strip the DTD even when a "]" appears inside a
     * DTD comment, so no internal-subset fragment leaks past the parser.
     *
     * @test
     */
    public function doctypeWithBracketInCommentIsFullyStripped()
    {
        $svg = "<!DOCTYPE svg [ <!-- ] --> <!ENTITY x \"y\"> ]>\n"
            . '<svg xmlns="http://www.w3.org/2000/svg"><rect width="1" height="1"/></svg>';

        $sanitizer = new Sanitizer();
        $clean = $sanitizer->sanitize($svg);

        self::assertTrue(is_string($clean), 'document should remain valid after a full DTD strip');
        self::assertTrue(false !== strpos($clean, '<rect'), 'body should survive');
        self::assertTrue(false === stripos($clean, '<!ENTITY'), 'no DTD fragment should leak');
    }

    /**
     * removeDoctype() must fully strip the DTD even when a "]" appears inside an
     * entity value string.
     *
     * @test
     */
    public function doctypeWithBracketInEntityValueIsFullyStripped()
    {
        $svg = "<!DOCTYPE svg [ <!ENTITY x \"a]b\"> ]>\n"
            . '<svg xmlns="http://www.w3.org/2000/svg"><rect width="1" height="1"/></svg>';

        $sanitizer = new Sanitizer();
        $clean = $sanitizer->sanitize($svg);

        self::assertTrue(is_string($clean), 'document should remain valid after a full DTD strip');
        self::assertTrue(false !== strpos($clean, '<rect'), 'body should survive');
        self::assertTrue(false === stripos($clean, '<!ENTITY'), 'no DTD fragment should leak');
    }

    /**
     * Issue 3 follow-up: an escaped @import whose keyword and value are separated
     * by whitespace (which the detector strips) must still be removed.
     *
     * @test
     */
    public function removeRemoteReferencesStripsEscapedImportWithWhitespaceSeparator()
    {
        $svg = "<svg xmlns=\"http://www.w3.org/2000/svg\">"
            . "<style>@\\69 mport\n\"https://evil.com/track\";</style>"
            . "<rect width=\"1\" height=\"1\"/></svg>";

        $sanitizer = new Sanitizer();
        $sanitizer->removeRemoteReferences(true);
        $clean = $sanitizer->sanitize($svg);

        self::assertTrue(is_string($clean));
        self::assertTrue(false === strpos($clean, 'evil.com'), 'escaped @import with a newline separator should be removed');
    }

    /**
     * Issue 3 follow-up: image-set() can take a bare remote string (no url()
     * token), so a remote reference inside it must be stripped.
     *
     * @test
     */
    public function removeRemoteReferencesStripsRemoteImageSet()
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg">'
            . '<style>x{background:image-set("https://evil.com/track" 1x)}</style>'
            . '<rect width="1" height="1"/></svg>';

        $sanitizer = new Sanitizer();
        $sanitizer->removeRemoteReferences(true);
        $clean = $sanitizer->sanitize($svg);

        self::assertTrue(is_string($clean));
        self::assertTrue(false === strpos($clean, 'evil.com'), 'remote image-set() should be removed');
    }

    /**
     * Issue 3 follow-up: the -webkit-image-set() prefixed form must be stripped too.
     *
     * @test
     */
    public function removeRemoteReferencesStripsRemoteWebkitImageSet()
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg">'
            . '<style>x{background:-webkit-image-set("https://evil.com/track" 1x)}</style>'
            . '<rect width="1" height="1"/></svg>';

        $sanitizer = new Sanitizer();
        $sanitizer->removeRemoteReferences(true);
        $clean = $sanitizer->sanitize($svg);

        self::assertTrue(is_string($clean));
        self::assertTrue(false === strpos($clean, 'evil.com'), 'remote -webkit-image-set() should be removed');
    }

    /**
     * Regression: a local image-set() (no remote target) must be preserved.
     *
     * @test
     */
    public function removeRemoteReferencesKeepsLocalImageSet()
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg">'
            . '<style>x{background:image-set("/local/a.png" 1x)}</style>'
            . '<rect width="1" height="1"/></svg>';

        $sanitizer = new Sanitizer();
        $sanitizer->removeRemoteReferences(true);
        $clean = $sanitizer->sanitize($svg);

        self::assertTrue(is_string($clean));
        self::assertTrue(false !== strpos($clean, 'image-set'), 'local image-set() should be kept');
        self::assertTrue(false !== strpos($clean, '/local/a.png'), 'local image-set() target should be kept');
    }

    /**
     * Issue 3 follow-up: an escaped url() inside a style *attribute* (CSS) must be
     * stripped, just like inside a <style> element.
     *
     * @test
     */
    public function removeRemoteReferencesStripsEscapedUrlInStyleAttribute()
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg">'
            . '<rect style="background:\\75 rl(https://evil.com/track)" width="1" height="1"/></svg>';

        $sanitizer = new Sanitizer();
        $sanitizer->removeRemoteReferences(true);
        $clean = $sanitizer->sanitize($svg);

        self::assertTrue(is_string($clean));
        self::assertTrue(false === strpos($clean, 'evil.com'), 'escaped url() in a style attribute should be removed');
    }

    /**
     * Issue 3 follow-up: a remote image-set() inside a style attribute must be
     * stripped too.
     *
     * @test
     */
    public function removeRemoteReferencesStripsImageSetInStyleAttribute()
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg">'
            . '<rect style="background:image-set(&apos;https://evil.com/track&apos; 1x)" width="1" height="1"/></svg>';

        $sanitizer = new Sanitizer();
        $sanitizer->removeRemoteReferences(true);
        $clean = $sanitizer->sanitize($svg);

        self::assertTrue(is_string($clean));
        self::assertTrue(false === strpos($clean, 'evil.com'), 'remote image-set() in a style attribute should be removed');
    }

    /**
     * Regression: a legitimate escaped style attribute with no remote reference
     * must be preserved.
     *
     * @test
     */
    public function removeRemoteReferencesKeepsLegitimateEscapedStyleAttribute()
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg">'
            . '<rect style="fill:\\72 ed" width="1" height="1"/></svg>';

        $sanitizer = new Sanitizer();
        $sanitizer->removeRemoteReferences(true);
        $clean = $sanitizer->sanitize($svg);

        self::assertTrue(is_string($clean));
        self::assertTrue(false !== strpos($clean, 'fill:\\72 ed'), 'legitimate escaped style attribute should be preserved');
    }

    /**
     * Issue 3 follow-up: an unclosed url( inside a <style> element (the token is
     * closed implicitly at } / end-of-stylesheet by a CSS tokenizer, and still
     * fetches) must be stripped.
     *
     * @test
     */
    public function removeRemoteReferencesStripsUnclosedRemoteUrlInStyleElement()
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg">'
            . '<style>x{background:url(https://evil.com/track}</style>'
            . '<rect width="1" height="1"/></svg>';

        $sanitizer = new Sanitizer();
        $sanitizer->removeRemoteReferences(true);
        $clean = $sanitizer->sanitize($svg);

        self::assertTrue(is_string($clean));
        self::assertTrue(false === strpos($clean, 'evil.com'), 'unclosed remote url() should be removed');
    }

    /**
     * Issue 3 follow-up: an unclosed image-set( inside a <style> element must be
     * stripped.
     *
     * @test
     */
    public function removeRemoteReferencesStripsUnclosedRemoteImageSetInStyleElement()
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg">'
            . '<style>x{background:image-set("https://evil.com/track" 1x}</style>'
            . '<rect width="1" height="1"/></svg>';

        $sanitizer = new Sanitizer();
        $sanitizer->removeRemoteReferences(true);
        $clean = $sanitizer->sanitize($svg);

        self::assertTrue(is_string($clean));
        self::assertTrue(false === strpos($clean, 'evil.com'), 'unclosed remote image-set() should be removed');
    }

    /**
     * Regression: stripping an unclosed remote url() must not eat a following rule.
     *
     * @test
     */
    public function removeRemoteReferencesKeepsRuleAfterUnclosedRemoteUrl()
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg">'
            . '<style>x{background:url(https://evil.com/track} y{color:red}</style>'
            . '<rect width="1" height="1"/></svg>';

        $sanitizer = new Sanitizer();
        $sanitizer->removeRemoteReferences(true);
        $clean = $sanitizer->sanitize($svg);

        self::assertTrue(is_string($clean));
        self::assertTrue(false === strpos($clean, 'evil.com'), 'unclosed remote url() should be removed');
        self::assertTrue(false !== strpos($clean, 'color:red'), 'a following rule should be preserved');
    }

    /**
     * Regression (reporter edge case): a declaration trailing an unclosed url()
     * within the same rule is folded into the stripped URL (as a CSS tokenizer
     * would), while a declaration before the url() is preserved.
     *
     * @test
     */
    public function removeRemoteReferencesStripsUnclosedRemoteUrlFollowedByDeclaration()
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg">'
            . '<style>x{color:red;background:url(https://evil.com/track;text-align:left}</style>'
            . '<rect width="1" height="1"/></svg>';

        $sanitizer = new Sanitizer();
        $sanitizer->removeRemoteReferences(true);
        $clean = $sanitizer->sanitize($svg);

        self::assertTrue(is_string($clean));
        self::assertTrue(false === strpos($clean, 'evil.com'), 'unclosed remote url() should be removed');
        self::assertTrue(false !== strpos($clean, 'color:red'), 'a declaration before the url() should be preserved');
    }

    /**
     * Regression: a closed remote url() with a ';' in its query string must still
     * be fully stripped (guards the rule-boundary change).
     *
     * @test
     */
    public function removeRemoteReferencesStripsClosedRemoteUrlWithSemicolon()
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg">'
            . '<style>x{background:url(https://evil.com/x?a=1;b=2)}</style>'
            . '<rect width="1" height="1"/></svg>';

        $sanitizer = new Sanitizer();
        $sanitizer->removeRemoteReferences(true);
        $clean = $sanitizer->sanitize($svg);

        self::assertTrue(is_string($clean));
        self::assertTrue(false === strpos($clean, 'evil.com'), 'closed remote url() with a semicolon should be removed');
    }


    /**
     * Test that disallowed nodes interleaved in an element-dense document
     * are all removed and that no sibling gets skipped along the way.
     */
    public function testSanitizeElementDenseSVG()
    {
        $count = 500;
        $initialData = '<svg xmlns="http://www.w3.org/2000/svg">'
            . str_repeat('<rect x="1" y="1" width="2" height="2"/><script>alert(1)</script>', $count)
            . '</svg>';

        $sanitizer = new Sanitizer();
        $cleanData = $sanitizer->sanitize($initialData);

        self::assertSame($count, substr_count($cleanData, '<rect'));
        self::assertSame(0, substr_count($cleanData, '<script'));
        self::assertCount($count, $sanitizer->getXmlIssues());
    }

    /**
     * Upper bound, in seconds, for the crafted inputs below that used to take
     * several seconds or more. The fixed code handles each of them in a few
     * milliseconds, so this leaves a wide margin for slow CI runners while still
     * failing loudly if the slow behaviour comes back.
     */
    const SLOW_INPUT_CEILING = 2.0;

    /**
     * Byte orders and BOM combinations libxml auto-detects as UTF-16.
     *
     * @return array<string, array{0: bool, 1: bool}>
     */
    public static function utf16EncodingDataProvider()
    {
        return [
            'UTF-16LE with BOM' => [false, true],
            'UTF-16BE with BOM' => [true, true],
            'UTF-16LE without BOM' => [false, false],
            'UTF-16BE without BOM' => [true, false],
        ];
    }

    /**
     * The DTD is stripped from the raw bytes before parsing. In UTF-16 every
     * character is followed or preceded by a NUL byte, so a byte search for
     * `<!DOCTYPE` never matches, while libxml still decodes the document and
     * defines the custom entity. The entity-collision payload must be rejected
     * whatever the input encoding.
     *
     * @test
     * @dataProvider utf16EncodingDataProvider
     */
    public function utf16EncodedEntityHrefBypassIsRejected($bigEndian, $withBom)
    {
        $dataDirectory = __DIR__ . '/data';
        $initialData = self::toUtf16(
            str_replace('encoding="UTF-8"', 'encoding="UTF-16"', file_get_contents($dataDirectory . '/entityHrefBypassTest.svg')),
            $bigEndian,
            $withBom
        );

        $sanitizer = new Sanitizer();
        $cleanData = $sanitizer->sanitize($initialData);

        self::assertFalse($cleanData);
    }

    /**
     * A UTF-16 DTD can also give `<use>` a default `href`, so the reference graph
     * sees `#ok` while the browser follows the real, non-fragment reference.
     *
     * @test
     */
    public function utf16EncodedAttlistDefaultIsRejected()
    {
        $svg = '<?xml version="1.0" encoding="UTF-16"?>'
            . '<!DOCTYPE svg [<!ATTLIST use href CDATA "#ok">]>'
            . '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">'
            . '<use xlink:href="/evil.svg"/></svg>';

        $sanitizer = new Sanitizer();
        $cleanData = $sanitizer->sanitize(self::toUtf16($svg, false, true));

        self::assertFalse($cleanData);
    }

    /**
     * Removing one DOCTYPE can join the text around it into a new, complete one.
     *
     * @return array<string, array{0: string}>
     */
    public static function splicedDoctypeDataProvider()
    {
        $body = '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">'
            . '<a xlink:href="&Tab;javascript:alert(1)"><text>x</text></a></svg>';

        return [
            'split after <!' => ['<!<!DOCTYPE x>DOCTYPE svg [<!ENTITY Tab "#">]>' . $body],
            'split inside the keyword' => ['<!DOC<!DOCTYPE x>TYPE svg [<!ENTITY Tab "#">]>' . $body],
            'nested twice' => ['<!DOC<!DOC<!DOCTYPE x>TYPE y>TYPE svg [<!ENTITY Tab "#">]>' . $body],
        ];
    }

    /**
     * @test
     * @dataProvider splicedDoctypeDataProvider
     */
    public function splicedDoctypeIsRejected($svg)
    {
        $sanitizer = new Sanitizer();
        $cleanData = $sanitizer->sanitize($svg);

        self::assertFalse($cleanData);
    }

    /**
     * Regression guard: a UTF-16 document without a DTD must keep sanitizing.
     *
     * @test
     * @dataProvider utf16EncodingDataProvider
     */
    public function utf16DocumentWithoutDtdStillSanitizes($bigEndian, $withBom)
    {
        $svg = '<?xml version="1.0" encoding="UTF-16"?>'
            . '<svg xmlns="http://www.w3.org/2000/svg"><rect width="10" height="10"/></svg>';

        $sanitizer = new Sanitizer();
        $cleanData = $sanitizer->sanitize(self::toUtf16($svg, $bigEndian, $withBom));

        self::assertTrue(is_string($cleanData));
        self::assertTrue(false !== strpos($cleanData, '<rect'), 'rect should survive');
    }

    /**
     * Regression guard: a UTF-16 document with an entity-free PUBLIC DOCTYPE (no
     * internal subset) must keep sanitizing, like its UTF-8 equivalent.
     *
     * @test
     */
    public function utf16DocumentWithPublicDoctypeStillSanitizes()
    {
        $svg = '<?xml version="1.0" encoding="UTF-16"?>'
            . '<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">'
            . '<svg xmlns="http://www.w3.org/2000/svg"><rect width="10" height="10"/></svg>';

        $sanitizer = new Sanitizer();
        $cleanData = $sanitizer->sanitize(self::toUtf16($svg, false, true));

        self::assertTrue(is_string($cleanData));
        self::assertTrue(false !== strpos($cleanData, '<rect'), 'rect should survive');
    }

    /**
     * Well-formed XML whose root is not a single `<svg>` must give the documented
     * `false`, not an uncaught exception.
     *
     * @return array<string, array{0: string}>
     */
    public static function nonSvgRootDataProvider()
    {
        return [
            'other root element' => ['<?xml version="1.0"?><root><child/></root>'],
            'svg nested under another root' => ['<html><body><svg xmlns="http://www.w3.org/2000/svg"></svg></body></html>'],
        ];
    }

    /**
     * @test
     * @dataProvider nonSvgRootDataProvider
     */
    public function nonSvgRootReturnsFalse($xml)
    {
        $sanitizer = new Sanitizer();
        $cleanData = $sanitizer->sanitize($xml);

        self::assertFalse($cleanData);
        self::assertTrue(count($sanitizer->getXmlIssues()) > 0, 'the reason should be reported');
    }

    /**
     * A `<use>` inside the element it references is an infinite loop. It must be
     * removed, not crash the sanitizer, however deeply it is nested.
     *
     * @return array<string, array{0: string, 1: string}>
     */
    public static function useReferencingItsOwnAncestorDataProvider()
    {
        $open = '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">';

        return [
            'direct child, href' => [
                $open . '<g id="a"><use href="#a"/></g></svg>',
                $open . '<g id="a"></g></svg>',
            ],
            'direct child, xlink:href' => [
                $open . '<g id="a"><use xlink:href="#a"/></g></svg>',
                $open . '<g id="a"></g></svg>',
            ],
            'child of the root svg' => [
                '<svg xmlns="http://www.w3.org/2000/svg" id="a"><use href="#a"/></svg>',
                '<svg xmlns="http://www.w3.org/2000/svg" id="a"></svg>',
            ],
            'wrapped in a plain group' => [
                $open . '<g id="a"><g><use href="#a"/></g></g></svg>',
                $open . '<g id="a"><g></g></g></svg>',
            ],
            'inside a nested identified group' => [
                $open . '<g id="a"><g id="b"><use href="#a"/></g></g></svg>',
                $open . '<g id="a"><g id="b"></g></g></svg>',
            ],
        ];
    }

    /**
     * @test
     * @dataProvider useReferencingItsOwnAncestorDataProvider
     */
    public function useReferencingItsOwnAncestorIsRemoved($svg, $expected)
    {
        $sanitizer = new Sanitizer();
        $cleanData = $sanitizer->sanitize($svg);

        self::assertTrue(is_string($cleanData));
        self::assertXmlStringEqualsXmlString($expected, $cleanData);
    }

    /**
     * Wrapping each level's `<use>` elements in a plain `<g>` used to hide them
     * from the reference graph, so the billion-laughs fixture passed the
     * expansion threshold untouched. Wrapped, it must be cleaned exactly like
     * the unwrapped original.
     *
     * @test
     */
    public function useElementsInsidePlainGroupsCountTowardsTheThreshold()
    {
        $dataDirectory = __DIR__ . '/data';
        $initialData = self::wrapIdentifiedGroupContents(file_get_contents($dataDirectory . '/xlinkLaughsTest.svg'));
        $expected = self::wrapIdentifiedGroupContents(file_get_contents($dataDirectory . '/xlinkLaughsClean.svg'));

        $sanitizer = new Sanitizer();
        $sanitizer->minify(false);
        $cleanData = $sanitizer->sanitize($initialData);

        self::assertXmlStringEqualsXmlString($expected, $cleanData);
    }

    /**
     * Layered, loop-free `<use>` graphs whose depth stays within the nesting
     * limit: every element in one layer uses every element in the next, so the
     * number of distinct paths grows as fan-out ^ depth.
     *
     * @return array<string, array{0: int, 1: int}>
     */
    public static function layeredUseGraphDataProvider()
    {
        return [
            '12 layers of 4' => [12, 4],
            '15 layers of 3, at the nesting limit' => [15, 3],
        ];
    }

    /**
     * @test
     * @dataProvider layeredUseGraphDataProvider
     */
    public function layeredUseGraphIsAnalysedQuickly($layers, $fanOut)
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg">';
        for ($layer = 0; $layer < $layers; $layer++) {
            for ($node = 0; $node < $fanOut; $node++) {
                $svg .= '<g id="n_' . $layer . '_' . $node . '">';
                if ($layer < $layers - 1) {
                    for ($next = 0; $next < $fanOut; $next++) {
                        $svg .= '<use href="#n_' . ($layer + 1) . '_' . $next . '"/>';
                    }
                }
                $svg .= '</g>';
            }
        }
        $svg .= '</svg>';

        $sanitizer = new Sanitizer();
        $started = microtime(true);
        $cleanData = $sanitizer->sanitize($svg);
        $elapsed = microtime(true) - $started;

        self::assertTrue($elapsed < self::SLOW_INPUT_CEILING, sprintf('took %.2fs', $elapsed));
        self::assertTrue(is_string($cleanData));
        self::assertTrue(self::largestUseExpansion($cleanData) < 10000, 'surviving <use> elements must not expand without bound');
    }

    /**
     * Nested PHP tags are peeled one layer at a time. Each layer used to cost a
     * full regex pass over the whole input, so the work grew with the square of
     * the input size.
     *
     * @test
     */
    public function deeplyNestedPhpTagsAreStrippedQuickly()
    {
        $nesting = 16000;
        $svg = str_repeat('<?p', $nesting) . '<?phpX?>' . str_repeat('hpY?>', $nesting)
            . '<svg xmlns="http://www.w3.org/2000/svg"><rect width="10" height="10"/></svg>';

        $sanitizer = new Sanitizer();
        $started = microtime(true);
        $cleanData = $sanitizer->sanitize($svg);
        $elapsed = microtime(true) - $started;

        self::assertTrue($elapsed < self::SLOW_INPUT_CEILING, sprintf('took %.2fs', $elapsed));
        self::assertTrue(is_string($cleanData));
        self::assertTrue(false === stripos($cleanData, '<?php'), 'no PHP tag may survive');
        self::assertTrue(false !== strpos($cleanData, '<rect'), 'rect should survive');
    }

    /**
     * Without PCRE's JIT, a single pass of the old PHP-tag regex was quadratic on
     * a long line of openers whose only closer sits on the next line.
     *
     * @test
     */
    public function unclosedPhpTagsOnOneLineAreHandledQuicklyWithoutJit()
    {
        $svg = str_repeat('<?php ', 20000) . "\n?>"
            . '<svg xmlns="http://www.w3.org/2000/svg"><rect width="10" height="10"/></svg>';

        $result = self::withIniSettings(['pcre.jit' => '0'], function () use ($svg) {
            $sanitizer = new Sanitizer();
            $started = microtime(true);
            $cleanData = $sanitizer->sanitize($svg);

            return [$cleanData, microtime(true) - $started];
        });

        self::assertTrue($result[1] < self::SLOW_INPUT_CEILING, sprintf('took %.2fs', $result[1]));
        self::assertTrue(false === $result[0] || false === stripos($result[0], '<?php'), 'no PHP tag may survive');
    }

    /**
     * Regression guard for the PHP-tag stripper: tags hidden by interleaving, the
     * short echo form and mixed case must all be removed, and the document must
     * still sanitize.
     *
     * @return array<string, array{0: string}>
     */
    public static function hiddenPhpTagDataProvider()
    {
        return [
            'interleaved' => ['<?p<?php test?>hp echo 1;?>'],
            'interleaved short echo' => ['<?<?= 1?>= 2?>'],
            'mixed case' => ['<?PhP echo 1;?>'],
            'interleaved twice' => ['<?p<?p<?php a?>hp b?>hp c?>'],
        ];
    }

    /**
     * @test
     * @dataProvider hiddenPhpTagDataProvider
     */
    public function hiddenPhpTagsAreStripped($php)
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg">' . $php . '<rect width="10" height="10"/></svg>';

        $sanitizer = new Sanitizer();
        $cleanData = $sanitizer->sanitize($svg);

        self::assertTrue(is_string($cleanData));
        self::assertTrue(false === stripos($cleanData, '<?php'), 'no <?php may survive');
        self::assertTrue(false === strpos($cleanData, '<?='), 'no <?= may survive');
        self::assertTrue(false !== strpos($cleanData, '<rect'), 'rect should survive');
    }

    /**
     * Regression guard: a PHP block spanning several lines reaches the parser as a
     * processing instruction and is removed there.
     *
     * @test
     */
    public function multiLinePhpBlockIsRemoved()
    {
        $svg = "<svg xmlns=\"http://www.w3.org/2000/svg\"><?php\necho 1;\n?><rect width=\"10\" height=\"10\"/></svg>";

        $sanitizer = new Sanitizer();
        $cleanData = $sanitizer->sanitize($svg);

        self::assertTrue(is_string($cleanData));
        self::assertTrue(false === stripos($cleanData, '<?php'), 'no PHP block may survive');
        self::assertTrue(false !== strpos($cleanData, '<rect'), 'rect should survive');
    }

    /**
     * Many unclosed `image-set('` tokens used to make the remote-reference regex
     * rescan the rest of the stylesheet from every token.
     *
     * @test
     */
    public function manyUnclosedImageSetsAreStrippedQuickly()
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg"><style>'
            . str_repeat("-webkit-image-set('", 30000)
            . '</style></svg>';

        $result = self::withIniSettings(['pcre.jit' => '1'], function () use ($svg) {
            $sanitizer = new Sanitizer();
            $sanitizer->removeRemoteReferences(true);
            $started = microtime(true);
            $cleanData = $sanitizer->sanitize($svg);

            return [$cleanData, microtime(true) - $started];
        });

        self::assertTrue($result[1] < self::SLOW_INPUT_CEILING, sprintf('took %.2fs', $result[1]));
        self::assertTrue(is_string($result[0]));
    }

    /**
     * When PCRE gave up on the image-set input, `preg_replace()` returned null and
     * assigning that to `textContent` threw a TypeError out of `sanitize()`.
     *
     * @test
     */
    public function imageSetInputThatOverwhelmsPcreDoesNotThrow()
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg"><style>'
            . str_repeat("-webkit-image-set('", 50000)
            . '</style></svg>';

        $sanitizer = new Sanitizer();
        $sanitizer->removeRemoteReferences(true);
        $cleanData = $sanitizer->sanitize($svg);

        self::assertTrue(is_string($cleanData));
    }

    /**
     * If any regex fails (backtrack or recursion limit), `sanitize()` must fail
     * closed with `false` instead of throwing or returning half-cleaned output.
     *
     * @test
     */
    public function regexFailureMakesSanitizeReturnFalse()
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">'
            . '<style>.a{fill:url(https://evil.example/x)}</style>'
            . '<a xlink:href="https://example.com/"><rect width="10" height="10"/></a></svg>';

        $cleanData = self::withIniSettings(
            ['pcre.jit' => '0', 'pcre.backtrack_limit' => '1', 'pcre.recursion_limit' => '1'],
            function () use ($svg) {
                $sanitizer = new Sanitizer();
                $sanitizer->removeRemoteReferences(true);

                return $sanitizer->sanitize($svg);
            }
        );

        self::assertFalse($cleanData);
    }

    /**
     * Two ways past `removeRemoteReferences(true)`: CSS escapes in presentation
     * attributes (`fill="url(\2f\2f host)"`), and a backslash in the authority
     * (`/\host`), which browsers treat as `//host`. Local references must stay.
     *
     * @test
     */
    public function removeRemoteReferencesStripsEscapedAndBackslashReferences()
    {
        $dataDirectory = __DIR__ . '/data';
        $initialData = file_get_contents($dataDirectory . '/remoteReferenceBypassTest.svg');
        $expected = file_get_contents($dataDirectory . '/remoteReferenceBypassClean.svg');

        $sanitizer = new Sanitizer();
        $sanitizer->minify(false);
        $sanitizer->removeRemoteReferences(true);
        $cleanData = $sanitizer->sanitize($initialData);

        self::assertXmlStringEqualsXmlString($expected, $cleanData);
    }

    /**
     * A remote `image-set()` target written with a backslash authority must be
     * stripped like its `//` equivalent.
     *
     * @test
     */
    public function removeRemoteReferencesStripsBackslashImageSet()
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg">'
            . '<style>x{background:image-set("/\\5c evil.example/track" 1x)}</style>'
            . '<rect width="1" height="1"/></svg>';

        $sanitizer = new Sanitizer();
        $sanitizer->removeRemoteReferences(true);
        $clean = $sanitizer->sanitize($svg);

        self::assertTrue(is_string($clean));
        self::assertTrue(false === strpos($clean, 'evil.example'), 'backslash-authority image-set() should be removed');
    }

    /**
     * Looking up the element a `<use>` points at used to scan every element with
     * an id, once per `<use>`, so many ids plus many uses was quadratic.
     *
     * @test
     */
    public function manyIdsAndManyUsesAreSanitizedQuickly()
    {
        $count = 8000;
        $svg = '<svg xmlns="http://www.w3.org/2000/svg">';
        for ($i = 0; $i < $count; $i++) {
            $svg .= '<g id="i' . $i . '"/>';
        }
        $svg .= str_repeat('<use href="#missing"/>', $count) . '</svg>';

        $sanitizer = new Sanitizer();
        $started = microtime(true);
        $cleanData = $sanitizer->sanitize($svg);
        $elapsed = microtime(true) - $started;

        self::assertTrue($elapsed < self::SLOW_INPUT_CEILING, sprintf('took %.2fs', $elapsed));
        self::assertTrue(is_string($cleanData));
        self::assertSame($count, substr_count($cleanData, '<use'), 'uses of a missing id expand to nothing and stay');
    }

    /**
     * Every identified ancestor of a `<use>` must account for it, but listing all
     * nested `<use>` elements once per ancestor was depth x uses.
     *
     * @test
     */
    public function deeplyNestedIdsWithManyUsesAreSanitizedQuickly()
    {
        $depth = 250;
        $count = 30000;
        $svg = '<svg xmlns="http://www.w3.org/2000/svg">';
        for ($i = 0; $i < $depth; $i++) {
            $svg .= '<g id="g' . $i . '">';
        }
        $svg .= str_repeat('<use href="#leaf"/>', $count) . str_repeat('</g>', $depth)
            . '<rect id="leaf" width="1" height="1"/></svg>';

        $sanitizer = new Sanitizer();
        $started = microtime(true);
        $cleanData = $sanitizer->sanitize($svg);
        $elapsed = microtime(true) - $started;

        self::assertTrue($elapsed < self::SLOW_INPUT_CEILING, sprintf('took %.2fs', $elapsed));
        self::assertTrue(is_string($cleanData));
        self::assertSame($count, substr_count($cleanData, '<use'), 'uses of a plain rect stay');
    }

    /**
     * Each node used to be checked against the whole list of elements marked for
     * removal, even text nodes that can never be on it.
     *
     * @test
     */
    public function manySelfReferencesAmongManyNodesAreSanitizedQuickly()
    {
        $count = 20000;
        $svg = '<svg xmlns="http://www.w3.org/2000/svg">';
        for ($i = 0; $i < $count; $i++) {
            $svg .= '<g id="a' . $i . '"><use href="#a' . $i . '"/></g>';
        }
        $svg .= str_repeat('<text>x</text>', $count) . '</svg>';

        $sanitizer = new Sanitizer();
        $started = microtime(true);
        $cleanData = $sanitizer->sanitize($svg);
        $elapsed = microtime(true) - $started;

        self::assertTrue($elapsed < self::SLOW_INPUT_CEILING, sprintf('took %.2fs', $elapsed));
        self::assertTrue(is_string($cleanData));
        self::assertSame(0, substr_count($cleanData, '<use'), 'every self reference is removed');
        self::assertSame($count, substr_count($cleanData, '<text'), 'text survives');
    }

    /**
     * Each element used to have its whole subtree re-walked for unsafe nodes,
     * on top of the main walk, so deep nesting multiplied the work by the depth.
     *
     * @test
     */
    public function deeplyNestedDocumentIsSanitizedQuickly()
    {
        $depth = 250;
        $count = 80000;
        $svg = '<svg xmlns="http://www.w3.org/2000/svg">' . str_repeat('<g>', $depth)
            . str_repeat('<rect width="1" height="1"/><!-- c -->', $count)
            . str_repeat('</g>', $depth) . '</svg>';

        $sanitizer = new Sanitizer();
        $started = microtime(true);
        $cleanData = $sanitizer->sanitize($svg);
        $elapsed = microtime(true) - $started;

        self::assertTrue($elapsed < self::SLOW_INPUT_CEILING, sprintf('took %.2fs', $elapsed));
        self::assertTrue(is_string($cleanData));
        self::assertSame($count, substr_count($cleanData, '<rect'), 'rects survive');
        self::assertSame(0, substr_count($cleanData, '<!--'), 'comments are removed');
    }

    /**
     * Browsers resolve `#id` to the first element with that id. The reference
     * graph used to keep the last one, so empty decoys with the same ids, placed
     * after the real groups, hid the whole billion-laughs chain from the
     * expansion threshold.
     *
     * @test
     */
    public function duplicateIdDecoysDoNotHideUseExpansion()
    {
        $decoys = '<defs>';
        for ($i = 1; $i <= 10; $i++) {
            $decoys .= '<g id="a' . $i . '"/>';
        }
        $decoys .= '</defs></svg>';

        // Later duplicates lose their id, so the decoys come back as plain groups.
        $cleanDecoys = '<defs>' . str_repeat('<g/>', 10) . '</defs></svg>';

        $dataDirectory = __DIR__ . '/data';
        $initialData = str_replace('</svg>', $decoys, file_get_contents($dataDirectory . '/xlinkLaughsTest.svg'));
        $expected = str_replace('</svg>', $cleanDecoys, file_get_contents($dataDirectory . '/xlinkLaughsClean.svg'));

        $sanitizer = new Sanitizer();
        $sanitizer->minify(false);
        $cleanData = $sanitizer->sanitize($initialData);

        self::assertXmlStringEqualsXmlString($expected, $cleanData);
    }

    /**
     * Input that strips down to nothing (only PHP tags, or only a DOCTYPE) must
     * give `false`, not reach `loadXML('')`, which throws a ValueError on PHP 8.
     *
     * @return array<string, array{0: string}>
     */
    public static function emptyAfterStrippingDataProvider()
    {
        return [
            'PHP block only' => ['<?php echo 1; ?>'],
            'short echo only' => ['<?= ?>'],
            'interleaved PHP blocks only' => ['<?p<?php a?>hp b?>'],
            'DOCTYPE only' => ['<!DOCTYPE svg>'],
        ];
    }

    /**
     * @test
     * @dataProvider emptyAfterStrippingDataProvider
     */
    public function inputThatIsEmptyAfterStrippingReturnsFalse($input)
    {
        $sanitizer = new Sanitizer();

        self::assertFalse($sanitizer->sanitize($input));
    }

    /**
     * Regression guard: the byte-level DOCTYPE stripper cannot read UTF-7, so the
     * check after parsing must catch a DTD libxml decodes from it.
     *
     * @test
     */
    public function utf7EncodedDtdIsRejected()
    {
        $payload = '<!DOCTYPE svg [<!ENTITY Tab "#">]>'
            . '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">'
            . '<a xlink:href="&Tab;javascript:alert(1)"><text>x</text></a></svg>';
        $svg = '<?xml version="1.0" encoding="UTF-7"?>'
            . str_replace(['<', '>', '[', ']', '!'], ['+ADw-', '+AD4-', '+AFs-', '+AF0-', '+ACE-'], $payload);

        $sanitizer = new Sanitizer();

        self::assertFalse($sanitizer->sanitize($svg));
    }

    /**
     * A `<use>` with its own id renders its target, so it is a link in the chain
     * like any other element. Routing each layer of a billion-laughs chain
     * through `<use id="Un" href="#Ln">` used to hide the whole expansion.
     *
     * @test
     */
    public function useElementsWithTheirOwnIdCountTowardsTheThreshold()
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg"><g id="L0"><rect width="1" height="1"/></g>';
        for ($i = 0; $i < 9; $i++) {
            $svg .= '<use id="U' . $i . '" href="#L' . $i . '"/>';
            $svg .= '<g id="L' . ($i + 1) . '">' . str_repeat('<use href="#U' . $i . '"/>', 10) . '</g>';
        }
        $svg .= '<use href="#L9"/></svg>';

        $sanitizer = new Sanitizer();
        $cleanData = $sanitizer->sanitize($svg);

        self::assertTrue(is_string($cleanData));
        self::assertTrue(self::renderedUseExpansion($cleanData) < 10000, 'surviving <use> elements must not expand without bound');
    }

    /**
     * The same blind spot let a chain of identified `<use>` elements nest past
     * the nesting limit.
     *
     * @return array<string, array{0: string, 1: int}>
     */
    public static function identifiedUseChainDataProvider()
    {
        $longChain = '<svg xmlns="http://www.w3.org/2000/svg"><g id="L0"><rect width="1" height="1"/></g>';
        for ($i = 0; $i < 20; $i++) {
            $longChain .= '<use id="U' . $i . '" href="#L' . $i . '"/>';
            $longChain .= '<g id="L' . ($i + 1) . '"><use href="#U' . $i . '"/></g>';
        }
        $longChain .= '<use href="#L20"/></svg>';

        $shortChain = '<svg xmlns="http://www.w3.org/2000/svg"><g id="leaf"><rect/></g>'
            . '<use id="u0" href="#leaf"/><use id="u1" href="#u0"/><use id="u2" href="#u1"/><use id="u3" href="#u2"/></svg>';

        return [
            'forty links, default limit' => [$longChain, 15],
            'four links, limit of two' => [$shortChain, 2],
        ];
    }

    /**
     * @test
     * @dataProvider identifiedUseChainDataProvider
     */
    public function useElementsWithTheirOwnIdCountTowardsTheNestingLimit($svg, $limit)
    {
        $sanitizer = new Sanitizer();
        $sanitizer->setUseNestingLimit($limit);
        $cleanData = $sanitizer->sanitize($svg);

        self::assertTrue(is_string($cleanData));
        self::assertTrue(self::deepestRenderedUseNesting($cleanData) <= $limit, 'surviving <use> elements must stay within the nesting limit');
    }

    /**
     * A `<use>` that references itself, or two identified `<use>` elements that
     * reference each other, form a loop.
     *
     * @return array<string, array{0: string}>
     */
    public static function useLoopDataProvider()
    {
        return [
            'a use that references itself' => ['<svg xmlns="http://www.w3.org/2000/svg"><use id="a" href="#a"/></svg>'],
            'two uses that reference each other' => ['<svg xmlns="http://www.w3.org/2000/svg"><use id="a" href="#b"/><use id="b" href="#a"/></svg>'],
        ];
    }

    /**
     * @test
     * @dataProvider useLoopDataProvider
     */
    public function useElementsWithTheirOwnIdCannotHideALoop($svg)
    {
        $sanitizer = new Sanitizer();
        $cleanData = $sanitizer->sanitize($svg);

        self::assertTrue(is_string($cleanData));
        self::assertTrue(self::renderedUseExpansion($cleanData) !== INF, 'the loop must be broken');
    }

    /**
     * When the first element with an id is one the cleaner removes, a browser
     * resolves `#id` to the next element with that id. Duplicate ids must not
     * let the graph measure a different element from the one that renders.
     *
     * @return array<string, array{0: string}>
     */
    public static function removedDecoyDataProvider()
    {
        return [
            'disallowed tag' => ['<foo id="%s"/>'],
            'script' => ['<script id="%s"/>'],
            'font with face' => ['<font id="%s" face="x"/>'],
            'use with a remote href' => ['<use id="%s" href="https://example.com/x.svg#a"/>'],
        ];
    }

    /**
     * @test
     * @dataProvider removedDecoyDataProvider
     */
    public function duplicateIdDecoysThatTheCleanerRemovesDoNotHideUseExpansion($decoyTemplate)
    {
        $decoys = '';
        for ($i = 1; $i <= 10; $i++) {
            $decoys .= sprintf($decoyTemplate, 'a' . $i);
        }

        $dataDirectory = __DIR__ . '/data';
        $initialData = preg_replace('/<defs>/', '<defs>' . $decoys, file_get_contents($dataDirectory . '/xlinkLaughsTest.svg'), 1);

        $sanitizer = new Sanitizer();
        $cleanData = $sanitizer->sanitize($initialData);

        self::assertTrue(is_string($cleanData));
        self::assertTrue(self::renderedUseExpansion($cleanData) < 10000, 'surviving <use> elements must not expand without bound');
    }

    /**
     * Every element after the first with a given id loses its `id`, so each id
     * has exactly one possible target. A `<use>` inside a later duplicate
     * references the first element, not its own ancestor, so it stays.
     *
     * @test
     */
    public function laterDuplicateIdsAreRemoved()
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg"><rect id="a"/><g id="a"><use href="#a"/></g></svg>';
        $expected = '<svg xmlns="http://www.w3.org/2000/svg"><rect id="a"/><g><use href="#a"/></g></svg>';

        $sanitizer = new Sanitizer();
        $cleanData = $sanitizer->sanitize($svg);

        self::assertXmlStringEqualsXmlString($expected, $cleanData);
    }

    /**
     * The graph and the cleaned output must agree on which `href` a `<use>`
     * follows. Normalising `HrEf` must not overwrite an `href` the graph already
     * read, and sanitizing the output again must not change it.
     *
     * @return array<string, array{0: string}>
     */
    public static function competingHrefDataProvider()
    {
        return [
            'href and HrEf' => ['<g id="a"><use href="#missing" HrEf="#b"/><use href="#missing" HrEf="#b"/></g>'],
            'HREF and xlink:href' => ['<g id="a"><use HREF="#missing" xlink:href="#b"/><use HREF="#missing" xlink:href="#b"/></g>'],
            'xlink:href and xlink:HREF' => ['<g id="a"><use xlink:href="#missing" xlink:HREF="#b"/><use xlink:href="#missing" xlink:HREF="#b"/></g>'],
            'HREF and an empty xlink:href' => ['<g id="a"><use HREF="#b" xlink:href=""/><use HREF="#b" xlink:href=""/></g>'],
            // Removing the unsafe href makes the xlink:href the live reference.
            'unsafe href hiding xlink:href' => ['<g id="a"><use href="javascript:void(0)" xlink:href="#b"/><use href="javascript:void(0)" xlink:href="#b"/></g>'],
        ];
    }

    /**
     * Without an `xmlns:xlink` declaration, every `xlink:href` spelling is
     * removed in one pass. Removing attributes while iterating the live
     * attribute map used to skip the one after each removal.
     *
     * @test
     */
    public function everyUnboundXlinkHrefIsRemovedInOnePass()
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg"><use xlink:href="#a" xlink:HREF="#b"/>'
            . '<radialGradient xlink:href="" XLINk:Href="data:image/png"/></svg>';

        $sanitizer = new Sanitizer();
        $first = $sanitizer->sanitize($svg);
        $second = $sanitizer->sanitize($first);

        self::assertTrue(is_string($first) && is_string($second));
        self::assertTrue(false === stripos($first, 'xlink:href'), 'every unbound xlink:href spelling should be removed');
        self::assertXmlStringEqualsXmlString($first, $second);
    }

    /**
     * @test
     * @dataProvider competingHrefDataProvider
     */
    public function competingHrefSpellingsCannotChangeTheGraphAfterAnalysis($group)
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">'
            . $group . '<g id="b"><rect/></g><use id="outer" href="#a"/></svg>';

        $sanitizer = new Sanitizer();
        $sanitizer->useThreshold(2);
        $cleanData = $sanitizer->sanitize($svg);

        self::assertTrue(is_string($cleanData));
        self::assertFalse(self::outerUseSurvivesWithTwoLiveReferences($cleanData), 'the outer <use> must not survive with two live references below it');

        $again = new Sanitizer();
        $again->useThreshold(2);
        self::assertXmlStringEqualsXmlString($cleanData, $again->sanitize($cleanData));
    }

    /**
     * `#%61` addresses the element with id `a`, because a fragment is
     * percent-decoded. The graph must resolve it the same way.
     *
     * @test
     */
    public function percentEncodedFragmentsReachTheSameTarget()
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg">'
            . '<g id="a"><use href="#b"/><use href="#b"/></g><g id="b"><rect/></g>'
            . '<use id="outer" href="#%61"/></svg>';

        $sanitizer = new Sanitizer();
        $sanitizer->useThreshold(2);
        $cleanData = $sanitizer->sanitize($svg);

        self::assertTrue(is_string($cleanData));
        self::assertFalse(self::outerUseSurvivesWithTwoLiveReferences($cleanData), 'the outer <use> must not survive with two live references below it');
    }

    /**
     * An HTML parser lower-cases `<USE>` and `ID` when the output is inlined in a
     * page, so upper-case spellings must not hide a chain from the graph.
     *
     * @test
     */
    public function upperCaseUseAndIdDoNotHideUseExpansion()
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg"><g ID="L0"><rect width="1" height="1"/></g>';
        for ($i = 1; $i <= 9; $i++) {
            $svg .= '<g ID="L' . $i . '">' . str_repeat('<USE href="#L' . ($i - 1) . '"/>', 10) . '</g>';
        }
        $svg .= '<USE href="#L9"/></svg>';

        $sanitizer = new Sanitizer();
        $cleanData = $sanitizer->sanitize($svg);

        self::assertTrue(is_string($cleanData));
        self::assertTrue(self::renderedUseExpansion($cleanData) < 10000, 'surviving <use> elements must not expand without bound once lower-cased');
    }

    /**
     * A `<use>` outside the SVG namespace is invisible to the reference graph, but
     * an HTML parser puts it back in the SVG namespace when the output is inlined
     * in a page.
     *
     * @return array<string, array{0: string}>
     */
    public static function foreignNamespaceUseDataProvider()
    {
        return [
            'empty namespace' => ['xmlns=""'],
            'another namespace' => ['xmlns="http://example.com/other"'],
        ];
    }

    /**
     * @test
     * @dataProvider foreignNamespaceUseDataProvider
     */
    public function useElementsOutsideTheSvgNamespaceDoNotHideUseExpansion($namespace)
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg"><g id="L0"><rect width="1" height="1"/></g>';
        for ($i = 1; $i <= 9; $i++) {
            $svg .= '<g id="L' . $i . '">' . str_repeat('<use ' . $namespace . ' href="#L' . ($i - 1) . '"/>', 10) . '</g>';
        }
        $svg .= '<use ' . $namespace . ' href="#L9"/></svg>';

        $sanitizer = new Sanitizer();
        $cleanData = $sanitizer->sanitize($svg);

        self::assertTrue(is_string($cleanData));
        self::assertTrue(self::renderedUseExpansion($cleanData) < 10000, 'surviving <use> elements must not expand without bound once inlined');
    }

    /**
     * More ways a remote reference used to get past removeRemoteReferences(true).
     *
     * @return array<string, array{0: string}>
     */
    public static function remoteCssBypassDataProvider()
    {
        return [
            // Removing one token joined the text around it into a new one.
            'removal rebuilds @import' => ['<style>@imp@import x;ort "//evil.example/a.css";</style>'],
            'removal rebuilds url()' => ['<style>rect{fill:uurl(//decoy.example)rl(//evil.example/a.svg#p)}</style>'],
            // An escaped `/*`, or a `/*` inside a string, is not a comment, but
            // the escaped url() between it and the next `*/` was deleted from
            // the checked copy only.
            'escaped comment in style attribute' => ['<rect style="a:\\2f\\2a;fill:\\75rl(//evil.example/a.svg#p);b:\\2a\\2f"/>'],
            'comment inside strings in style attribute' => ['<rect style="font-family:&quot;/*&quot;;fill:\\75rl(//evil.example/a.svg#p);font-family:&quot;*/&quot;"/>'],
            'escaped comment in style element' => ['<style>a{b:\\2f\\2a}rect{fill:\\75rl(//evil.example/a.svg#p)}a{b:\\2a\\2f}</style>'],
            // Browsers drop tab, CR and LF anywhere in a URL, and leading
            // control characters.
            'tab between the slashes' => ["<style>rect{fill:url(\"/\t/evil.example/a.svg#p\")}</style>"],
            'tab inside the scheme' => ["<style>rect{fill:url(\"ht\ttps://evil.example/a.svg#p\")}</style>"],
            'escaped tab inside the scheme' => ['<style>rect{fill:url("ht\\9 tps://evil.example/a.svg#p")}</style>'],
            'escaped leading control character' => ['<style>rect{fill:url("\\1 //evil.example/a.svg#p")}</style>'],
            'CR LF after a hex escape' => ["<style>rect{fill:url(\\2f&#13;\n/evil.example/a.svg#p)}</style>"],
            // A backslash before a line break continues a CSS string.
            'string line continuation' => ["<style>svg{fill:url(\"ht\\\ntps://evil.example/x\")}</style>"],
            // A `)` inside an earlier argument does not end image-set().
            'nested function before a remote image-set candidate' => ['<style>svg{background:image-set(linear-gradient(red,blue) 1x,"\\2f\\2f evil.example/x" 2x)}</style>'],
            'parenthesis inside a string before a remote image-set candidate' => ['<style>svg{background:image-set("a).png" 1x,"//evil.example/x" 2x)}</style>'],
            // A special scheme needs no slashes at all after the colon.
            'escaped scheme with one slash' => ['<style>svg{fill:url(\\68 ttps:/evil.example/x)}</style>'],
            'scheme with one slash in a style element' => ['<style>svg{fill:url(https:/evil.example/x)}</style>'],
            'scheme with no slash in a style element' => ['<style>svg{fill:url(https:evil.example/x)}</style>'],
            'scheme with one slash in an attribute' => ['<rect fill="url(https:/evil.example/x)"/>'],
            'scheme with one slash in an href' => ['<image href="http:/evil.example/x.png"/>'],
            'scheme with no slash in a style attribute' => ['<rect style="fill:url(https:evil.example/x)"/>'],
            'scheme with no slash in image-set()' => ['<style>rect{background:image-set("http:evil.example/x" 1x)}</style>'],
            'image-set() in a presentation attribute' => ['<rect mask="image-set(\'//evil.example/x\' 1x)"/>'],
        ];
    }

    /**
     * @test
     * @dataProvider remoteCssBypassDataProvider
     */
    public function remoteReferencesCannotBeRebuiltOrHidden($body)
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg">' . $body . '<rect width="1" height="1"/></svg>';

        $sanitizer = new Sanitizer();
        $sanitizer->removeRemoteReferences(true);
        $cleanData = $sanitizer->sanitize($svg);

        self::assertTrue(is_string($cleanData));
        self::assertTrue(false === strpos($cleanData, 'evil.example'), 'remote reference should be removed');
    }

    /**
     * Regression guard: ordinary CSS with comments, strings, gradients and local
     * image-set() candidates is left alone under removeRemoteReferences(true).
     *
     * @test
     */
    public function removeRemoteReferencesKeepsOrdinaryCss()
    {
        $css = '/* brand colours */ .a{fill:url(#grad);font-family:"Foo /* not a comment */ Bar"}'
            . ' .b{background:image-set(linear-gradient(red,blue) 1x,"/local/b.png" 2x)}';
        $svg = '<svg xmlns="http://www.w3.org/2000/svg"><style>' . $css . '</style>'
            . '<rect style="fill:url(#grad);stroke:\\72 ed" width="1" height="1"/></svg>';

        $sanitizer = new Sanitizer();
        $sanitizer->removeRemoteReferences(true);
        $cleanData = $sanitizer->sanitize($svg);

        self::assertTrue(is_string($cleanData));
        self::assertTrue(false !== strpos($cleanData, '.a{fill:url(#grad)'), 'local url() should stay');
        self::assertTrue(false !== strpos($cleanData, '"Foo /* not a comment */ Bar"'), 'strings should stay');
        self::assertTrue(false !== strpos($cleanData, '"/local/b.png" 2x'), 'local image-set() should stay');
        self::assertTrue(false !== strpos($cleanData, 'stroke:\\72 ed'), 'escaped style attribute should stay');
    }

    /**
     * A CSS escape for a UTF-16 surrogate must not put invalid UTF-8 into the
     * output.
     *
     * @test
     */
    public function cssEscapedSurrogatesStayValidUtf8()
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg">'
            . '<style>a{content:"\\D800"}b{fill:url(//evil.example/x)}</style></svg>';

        $sanitizer = new Sanitizer();
        $sanitizer->removeRemoteReferences(true);
        $cleanData = $sanitizer->sanitize($svg);

        self::assertTrue(is_string($cleanData));
        self::assertSame(1, preg_match('//u', $cleanData), 'output must be valid UTF-8');
    }

    /**
     * A long run of whitespace after `url(` or `@import` used to make the
     * remote-reference regexes backtrack over every way to split it.
     *
     * @return array<string, array{0: string}>
     */
    public static function longWhitespaceDataProvider()
    {
        $spaces = str_repeat(' ', 100000);

        return [
            'url( in a presentation attribute' => ['<rect fill="url(' . $spaces . 'x)"/>'],
            '@import in a style attribute' => ['<rect style="@import' . $spaces . 'x"/>'],
            'url( in a style element' => ['<style>a{fill:url(' . $spaces . 'x)}</style>'],
        ];
    }

    /**
     * @test
     * @dataProvider longWhitespaceDataProvider
     */
    public function longWhitespaceAfterUrlIsHandledQuickly($body)
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg">' . $body . '</svg>';

        $result = self::withIniSettings(['pcre.jit' => '1'], function () use ($svg) {
            $sanitizer = new Sanitizer();
            $sanitizer->removeRemoteReferences(true);
            $started = microtime(true);
            $cleanData = $sanitizer->sanitize($svg);

            return [$cleanData, microtime(true) - $started];
        });

        self::assertTrue($result[1] < self::SLOW_INPUT_CEILING, sprintf('took %.2fs', $result[1]));
        self::assertTrue(is_string($result[0]));
    }

    /**
     * Without PCRE's JIT, the comment regex retried the rest of the stylesheet
     * from every unclosed `/*`.
     *
     * @test
     */
    public function unclosedCssCommentsAreHandledQuicklyWithoutJit()
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg"><style>' . str_repeat('/*x', 16000) . '</style></svg>';

        $result = self::withIniSettings(['pcre.jit' => '0'], function () use ($svg) {
            $sanitizer = new Sanitizer();
            $sanitizer->removeRemoteReferences(true);
            $started = microtime(true);
            $cleanData = $sanitizer->sanitize($svg);

            return [$cleanData, microtime(true) - $started];
        });

        self::assertTrue($result[1] < self::SLOW_INPUT_CEILING, sprintf('took %.2fs', $result[1]));
        self::assertTrue(is_string($result[0]));
    }

    /**
     * One element with many attributes. Reading or removing each attribute by
     * name walks the element's attribute list from the start, which made the
     * attribute pass quadratic.
     *
     * @return array<string, array{0: string, 1: bool, 2: int}>
     */
    public static function manyAttributesDataProvider()
    {
        return [
            'allowed data attributes, remote references removed' => ['data-a%d="x"', true, 60000],
            'disallowed attributes, default settings' => ['bad-a%d="x"', false, 0],
            'href-like data attributes, default settings' => ['data-href%d="#a"', false, 60000],
        ];
    }

    /**
     * @test
     * @dataProvider manyAttributesDataProvider
     */
    public function manyAttributesOnOneElementAreSanitizedQuickly($template, $removeRemoteReferences, $expectedKept)
    {
        $attributes = '';
        for ($i = 0; $i < 60000; $i++) {
            $attributes .= ' ' . sprintf($template, $i);
        }
        $svg = '<svg xmlns="http://www.w3.org/2000/svg"><rect' . $attributes . '/></svg>';

        $sanitizer = new Sanitizer();
        $sanitizer->removeRemoteReferences($removeRemoteReferences);
        $started = microtime(true);
        $cleanData = $sanitizer->sanitize($svg);
        $elapsed = microtime(true) - $started;

        self::assertTrue($elapsed < self::SLOW_INPUT_CEILING, sprintf('took %.2fs', $elapsed));
        self::assertTrue(is_string($cleanData));

        $document = new \DOMDocument();
        $document->loadXML($cleanData);
        $rect = $document->getElementsByTagName('rect')->item(0);
        self::assertSame($expectedKept, $rect->attributes->length, 'allowed attributes stay and disallowed ones go');
    }

    /**
     * Before PHP 8.2, stripos() lower-cases the whole haystack on every call, so
     * calling it once per match with a growing offset is quadratic.
     *
     * @return array<string, array{0: string, 1: bool}>
     */
    public static function manyCaseInsensitiveMatchesDataProvider()
    {
        return [
            'many DOCTYPEs' => [str_repeat('<!DOCTYPE>', 150000) . '<svg xmlns="http://www.w3.org/2000/svg"/>', false],
            'many image-set tokens' => ['<svg xmlns="http://www.w3.org/2000/svg"><style>' . str_repeat('image-set', 150000) . '</style></svg>', true],
        ];
    }

    /**
     * @test
     * @dataProvider manyCaseInsensitiveMatchesDataProvider
     */
    public function manyCaseInsensitiveMatchesAreHandledQuickly($svg, $removeRemoteReferences)
    {
        $sanitizer = new Sanitizer();
        $sanitizer->removeRemoteReferences($removeRemoteReferences);
        $started = microtime(true);
        $sanitizer->sanitize($svg);
        $elapsed = microtime(true) - $started;

        self::assertTrue($elapsed < self::SLOW_INPUT_CEILING, sprintf('took %.2fs', $elapsed));
    }

    /**
     * Finding the root `<svg>` used to walk every `<svg>` in the document through
     * getElementsByTagName(), which before PHP 8.3 searches the document again
     * for each element.
     *
     * @test
     */
    public function manySvgElementsAreSanitizedQuickly()
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg">' . str_repeat('<svg/>', 60000) . '</svg>';

        $sanitizer = new Sanitizer();
        $started = microtime(true);
        $cleanData = $sanitizer->sanitize($svg);
        $elapsed = microtime(true) - $started;

        self::assertTrue($elapsed < self::SLOW_INPUT_CEILING, sprintf('took %.2fs', $elapsed));
        self::assertTrue(is_string($cleanData));
    }

    /**
     * The URL parser trims spaces and control characters from both ends of an
     * href and drops tabs and line breaks anywhere, so `#a ` and `#&#10;a`
     * both reach the element with id `a`. The graph must read them the same way.
     *
     * @return array<string, array{0: string}>
     */
    public static function whitespaceFragmentDataProvider()
    {
        return [
            'trailing space' => ['#a '],
            'leading space' => [' #a'],
            'trailing tab' => ['#a&#9;'],
            'trailing CR' => ['#a&#13;'],
            'newline inside' => ['#&#10;a'],
            'tab inside' => ['#&#9;a'],
        ];
    }

    /**
     * @test
     * @dataProvider whitespaceFragmentDataProvider
     */
    public function useFragmentsWithUrlWhitespaceReachTheSameTarget($href)
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg">'
            . '<g id="a"><use href="#b"/><use href="#b"/></g><g id="b"><rect/></g>'
            . '<use id="outer" href="' . $href . '"/></svg>';

        $sanitizer = new Sanitizer();
        $sanitizer->useThreshold(2);
        $cleanData = $sanitizer->sanitize($svg);

        self::assertTrue(is_string($cleanData));
        self::assertFalse(self::outerUseSurvivesWithTwoLiveReferences($cleanData), 'the outer <use> must not survive with two live references below it');
    }

    /**
     * The same gap at full scale: a billion-laughs chain whose references all
     * end in a space.
     *
     * @test
     */
    public function billionLaughsWithTrailingSpacesIsStopped()
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg"><g id="a0"><rect width="1" height="1"/></g>';
        for ($level = 1; $level <= 9; $level++) {
            $svg .= '<g id="a' . $level . '">' . str_repeat('<use href="#a' . ($level - 1) . ' "/>', 10) . '</g>';
        }
        $svg .= '<use href="#a9 "/></svg>';

        $sanitizer = new Sanitizer();
        $cleanData = $sanitizer->sanitize($svg);

        self::assertTrue(is_string($cleanData));
        self::assertTrue(self::renderedUseExpansion($cleanData) < 10000, 'surviving <use> elements must not expand without bound');
    }

    /**
     * Renaming `XLINK:href` to `xlink:href` must keep it in the XLink namespace.
     * When only a prefix like `XLINK` is bound, setAttribute('xlink:href') made
     * an attribute in no namespace, which the graph cannot see but an HTML
     * parser reads as XLink.
     *
     * @return array<string, array{0: string, 1: string}>
     */
    public static function unboundXlinkSpellingDataProvider()
    {
        return [
            'XLINK:href' => ['XLINK', 'XLINK:href'],
            'Xlink:HREF' => ['Xlink', 'Xlink:HREF'],
        ];
    }

    /**
     * @test
     * @dataProvider unboundXlinkSpellingDataProvider
     */
    public function renamedXlinkHrefStaysInTheXlinkNamespace($prefix, $attribute)
    {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg" xmlns:' . $prefix . '="http://www.w3.org/1999/xlink">'
            . '<g id="a"><use href="#b"/><use href="#b"/></g><g id="b"><rect/></g>'
            . '<use id="outer" ' . $attribute . '="#a"/></svg>';

        $sanitizer = new Sanitizer();
        $sanitizer->useThreshold(2);
        $cleanData = $sanitizer->sanitize($svg);

        self::assertTrue(is_string($cleanData));
        self::assertFalse(self::outerUseSurvivesWithTwoLiveReferences($cleanData), 'the outer <use> must not survive with two live references below it');

        $document = new \DOMDocument();
        self::assertTrue($document->loadXML($cleanData), 'the output must stay well-formed XML');
    }

    /**
     * More ways a remote `image-set()` URL got past removeRemoteReferences(true):
     * a comment holding `)`, a `{}` block inside a var() fallback, and a custom
     * property carrying the remote string.
     *
     * @return array<string, array{0: string}>
     */
    public static function remoteImageSetDataProvider()
    {
        return [
            'comment holding ) after a string holding /*' => ['x{content:"/*"} svg{mask-image:image-set(/* ) */ "https://evil.example/a.png" 1x)}'],
            '{} block in a var() fallback' => ['svg{--u:"x.png" 2x;mask-image:image-set(var(--u,{}), "https://evil.example/a.png" 1x)}'],
            'string in a custom property' => ['svg{--u:"https://evil.example/a.png";mask-image:image-set(var(--u) 1x)}'],
        ];
    }

    /**
     * @test
     * @dataProvider remoteImageSetDataProvider
     */
    public function remoteImageSetUrlsAreRemovedFromStyleElements($css)
    {
        $sanitizer = new Sanitizer();
        $sanitizer->removeRemoteReferences(true);
        $cleanData = $sanitizer->sanitize('<svg xmlns="http://www.w3.org/2000/svg"><style>' . $css . '</style></svg>');

        self::assertTrue(is_string($cleanData));
        self::assertTrue(false === strpos($cleanData, 'evil.example'), 'remote reference should be removed');
    }

    /**
     * @test
     * @dataProvider remoteImageSetDataProvider
     */
    public function remoteImageSetUrlsAreRemovedFromStyleAttributes($css)
    {
        $declarations = preg_replace('/^.*?svg\{|\}$/', '', $css);
        if (strpos($css, 'x{content:"/*"}') === 0) {
            $declarations = 'content:"/*";' . $declarations;
        }

        $sanitizer = new Sanitizer();
        $sanitizer->removeRemoteReferences(true);
        $cleanData = $sanitizer->sanitize(
            '<svg xmlns="http://www.w3.org/2000/svg"><rect style=\'' . htmlspecialchars($declarations, ENT_QUOTES) . '\'/></svg>'
        );

        self::assertTrue(is_string($cleanData));
        self::assertTrue(false === strpos($cleanData, 'evil.example'), 'remote reference should be removed');
    }

    /**
     * sanitize() must not raise any notice, including PHP 8.5 deprecations.
     *
     * @test
     */
    public function sanitizeRaisesNoNotices()
    {
        $notices = [];
        set_error_handler(function ($severity, $message) use (&$notices) {
            $notices[] = $message;

            return true;
        });

        try {
            $sanitizer = new Sanitizer();
            $cleanData = $sanitizer->sanitize('<svg xmlns="http://www.w3.org/2000/svg"><g id="a"><rect/></g><use href="#a"/></svg>');
        } finally {
            restore_error_handler();
        }

        self::assertTrue(is_string($cleanData));
        self::assertSame([], $notices);
    }

    /**
     * Encode an ASCII string as UTF-16.
     *
     * @param string $ascii
     * @param bool $bigEndian
     * @param bool $withBom
     * @return string
     */
    private static function toUtf16($ascii, $bigEndian, $withBom)
    {
        $encoded = $withBom ? ($bigEndian ? "\xFE\xFF" : "\xFF\xFE") : '';
        for ($i = 0, $length = strlen($ascii); $i < $length; $i++) {
            $encoded .= $bigEndian ? "\0" . $ascii[$i] : $ascii[$i] . "\0";
        }

        return $encoded;
    }

    /**
     * Run a callback with some ini settings changed, restoring them afterwards.
     *
     * @param array<string, string> $settings
     * @param callable $callback
     * @return mixed
     */
    private static function withIniSettings(array $settings, $callback)
    {
        $previous = [];
        foreach ($settings as $name => $value) {
            $previous[$name] = ini_get($name);
            ini_set($name, $value);
        }

        try {
            return $callback();
        } finally {
            foreach ($previous as $name => $value) {
                ini_set($name, $value);
            }
        }
    }

    /**
     * Index the document the way a browser resolves `#id`: the first element with
     * an id wins, and names match in any case, because an HTML parser lower-cases
     * them when the SVG is inlined in a page.
     *
     * @param string $svg
     * @return array{0: \DOMXPath, 1: array<string, \DOMElement>}
     */
    private static function indexRenderedDocument($svg)
    {
        $document = new \DOMDocument();
        $document->loadXML($svg);
        $xPath = new \DOMXPath($document);

        $byId = [];
        foreach ($xPath->query('//*') as $element) {
            foreach ($element->attributes as $attribute) {
                if (strtolower($attribute->nodeName) === 'id' && !isset($byId[$attribute->value])) {
                    $byId[$attribute->value] = $element;
                }
            }
        }

        return [$xPath, $byId];
    }

    /**
     * The element a `<use>` renders: a plain `href` in any case wins over
     * `xlink:href`, and the fragment is percent-decoded.
     *
     * @param \DOMElement $use
     * @param array<string, \DOMElement> $byId
     * @return \DOMElement|null
     */
    private static function renderedUseTarget(\DOMElement $use, array $byId)
    {
        $plain = null;
        $xlink = null;
        foreach ($use->attributes as $attribute) {
            // An attribute literally named `xlink:href` in no namespace is still
            // XLink to an HTML parser.
            $isUnboundXlink = strtolower($attribute->nodeName) === 'xlink:href' && (string) $attribute->prefix === '';
            if (strtolower($attribute->localName) !== 'href' && !$isUnboundXlink) {
                continue;
            }
            if ((string) $attribute->prefix === '' && !$isUnboundXlink) {
                $plain = $plain === null ? $attribute->value : $plain;
            } else {
                $xlink = $xlink === null ? $attribute->value : $xlink;
            }
        }
        $href = $plain !== null ? $plain : $xlink;
        if ($href === null) {
            return null;
        }
        // The URL parser trims spaces and control characters from both ends and
        // drops tabs and line breaks anywhere.
        $href = str_replace(["\t", "\n", "\r"], '', trim($href, "\x00..\x20"));
        if (strpos($href, '#') !== 0) {
            return null;
        }
        $id = rawurldecode(substr($href, 1));

        return isset($byId[$id]) ? $byId[$id] : null;
    }

    /**
     * Walk every surviving `<use>` as a browser renders it, counting `<use>`
     * elements at any depth inside the referenced element. $combine folds the
     * values of the nested uses. A reference loop gives INF.
     *
     * @param string $svg
     * @param callable $combine function (int|float $carry, int|float $value): int|float
     * @return float|int
     */
    private static function walkRenderedUses($svg, $combine)
    {
        list($xPath, $byId) = self::indexRenderedDocument($svg);
        $useQuery = "descendant-or-self::*[translate(local-name(), 'USE', 'use')='use']";

        $memo = [];
        $visiting = [];
        $walk = function (\DOMElement $use) use (&$walk, &$memo, &$visiting, $byId, $xPath, $useQuery, $combine) {
            $target = self::renderedUseTarget($use, $byId);
            if ($target === null) {
                return 1;
            }

            $key = spl_object_hash($target);
            if (isset($visiting[$key])) {
                return INF;
            }
            if (!isset($memo[$key])) {
                $visiting[$key] = true;
                $inner = 0;
                foreach ($xPath->query($useQuery, $target) as $nested) {
                    $inner = $combine($inner, $walk($nested));
                }
                unset($visiting[$key]);
                $memo[$key] = $inner;
            }

            return 1 + $memo[$key];
        };

        $largest = 0;
        foreach ($xPath->query("//*[translate(local-name(), 'USE', 'use')='use']") as $use) {
            $largest = max($largest, $walk($use));
        }

        return $largest;
    }

    /**
     * For the small threshold-of-two fixtures: does `<use id="outer">` survive
     * while group `a`, which it renders, holds two `<use>` elements that still
     * reach a real target? That is an expansion the threshold must stop.
     *
     * @param string $svg
     * @return bool
     */
    private static function outerUseSurvivesWithTwoLiveReferences($svg)
    {
        list($xPath, $byId) = self::indexRenderedDocument($svg);
        if (!isset($byId['outer'], $byId['a']) || self::renderedUseTarget($byId['outer'], $byId) !== $byId['a']) {
            return false;
        }

        $live = 0;
        foreach ($xPath->query("descendant::*[translate(local-name(), 'USE', 'use')='use']", $byId['a']) as $use) {
            if (self::renderedUseTarget($use, $byId) !== null) {
                $live++;
            }
        }

        return $live >= 2;
    }

    /**
     * The largest number of `<use>` instances any single surviving `<use>`
     * renders, the `<use>` itself included.
     *
     * @param string $svg
     * @return float|int
     */
    private static function renderedUseExpansion($svg)
    {
        return self::walkRenderedUses($svg, function ($carry, $value) {
            return $carry + $value;
        });
    }

    /**
     * The longest chain of nested `<use>` instances in the rendered document.
     *
     * @param string $svg
     * @return float|int
     */
    private static function deepestRenderedUseNesting($svg)
    {
        return self::walkRenderedUses($svg, function ($carry, $value) {
            return max($carry, $value);
        });
    }

    /**
     * Wrap the contents of every `<g id="aN">` in the billion-laughs fixtures in a
     * plain `<g>`. Those fixtures contain no other `<g>` elements.
     *
     * @param string $svg
     * @return string
     */
    private static function wrapIdentifiedGroupContents($svg)
    {
        $svg = preg_replace('/(<g id="a\d+">)/', '$1<g>', $svg);
        $svg = str_replace('</g>', '</g></g>', $svg);

        return preg_replace('/<g id="(a\d+)" \/>/', '<g id="$1"><g/></g>', $svg);
    }

    /**
     * The largest number of `<use>` instances any single `<use>` in the document
     * expands to when rendered, counting `<use>` elements at any depth inside the
     * referenced element. A reference loop counts as infinite.
     *
     * @param string $svg
     * @return float|int
     */
    private static function largestUseExpansion($svg)
    {
        $document = new \DOMDocument();
        $document->loadXML($svg);
        $xPath = new \DOMXPath($document);

        $byId = [];
        foreach ($xPath->query('//*[@id]') as $element) {
            $byId[$element->getAttribute('id')] = $element;
        }

        $memo = [];
        $visiting = [];
        $expand = function (\DOMElement $use) use (&$expand, &$memo, &$visiting, $byId, $xPath) {
            $href = $use->getAttribute('href');
            if ($href === '') {
                $href = $use->getAttributeNS('http://www.w3.org/1999/xlink', 'href');
            }
            if (strpos($href, '#') !== 0 || !isset($byId[substr($href, 1)])) {
                return 1;
            }

            $target = $byId[substr($href, 1)];
            $key = spl_object_hash($target);
            if (isset($visiting[$key])) {
                return INF;
            }
            if (!isset($memo[$key])) {
                $visiting[$key] = true;
                $inner = 0;
                foreach ($xPath->query("descendant-or-self::*[local-name()='use']", $target) as $nested) {
                    $inner += $expand($nested);
                }
                unset($visiting[$key]);
                $memo[$key] = $inner;
            }

            return 1 + $memo[$key];
        };

        $largest = 0;
        foreach ($xPath->query("//*[local-name()='use']") as $use) {
            $largest = max($largest, $expand($use));
        }

        return $largest;
    }
}
