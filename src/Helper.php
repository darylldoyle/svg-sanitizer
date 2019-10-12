<?php
namespace enshrined\svgSanitize;

class Helper
{
    /**
     * @param \DOMElement $element
     * @return string|null
     */
    public static function getElementHref(\DOMElement $element)
    {
        if ($element->hasAttribute('href')) {
            return $element->getAttribute('href');
        }
        if ($element->hasAttributeNS('http://www.w3.org/1999/xlink', 'href')) {
            return $element->getAttributeNS('http://www.w3.org/1999/xlink', 'href');
        }
        return null;
    }

    /**
     * @param string $href
     * @return string|null
     */
    public static function extractIdReferenceFromHref($href)
    {
        if (!is_string($href) || strpos($href, '#') !== 0) {
            return null;
        }
        return substr($href, 1);
    }
}
