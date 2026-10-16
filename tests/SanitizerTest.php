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
