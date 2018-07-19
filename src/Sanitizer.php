<?php

namespace enshrined\svgSanitize;

use DOMDocument;
use enshrined\svgSanitize\data\AllowedAttributes;
use enshrined\svgSanitize\data\AllowedTags;
use enshrined\svgSanitize\data\AttributeInterface;
use enshrined\svgSanitize\data\TagInterface;

/**
 * Class Sanitizer
 *
 * @package enshrined\svgSanitize
 */
class Sanitizer
{

    /**
     * Regex to catch script and data values in attributes
     */
    const SCRIPT_REGEX = '/(?:\w+script|data):/xi';

    /**
     * @var DOMDocument
     */
    protected $xmlDocument;

    /**
     * @var array
     */
    protected $allowedTags;

    /**
     * @var array
     */
    protected $allowedAttrs;

    /**
     * @var
     */
    protected $xmlLoaderValue;

    /**
     * @var bool
     */
    protected $minifyXML = false;

    /**
     * @var bool
     */
    protected $removeRemoteReferences = false;

    /**
     * @var bool
     */
    protected $removeXMLTag = false;

    /**
     * @var int
     */
    protected $xmlOptions = LIBXML_NOEMPTYTAG;

    /**
     *
     */
    function __construct()
    {
        // Load default tags/attributes
        $this->allowedAttrs = AllowedAttributes::getAttributes();
        $this->allowedTags = AllowedTags::getTags();
    }

    /**
     * Set up the DOMDocument
     */
    protected function resetInternal()
    {
        $this->xmlDocument = new DOMDocument();
        $this->xmlDocument->preserveWhiteSpace = false;
        $this->xmlDocument->strictErrorChecking = false;
        $this->xmlDocument->formatOutput = !$this->minifyXML;
    }

    /**
     * Set XML options to use when saving XML
     * See: DOMDocument::saveXML
     * 
     * @param int  $xmlOptions
     */
    public function setXMLOptions($xmlOptions)
    {
        $this->xmlOptions = $xmlOptions;
    }

     /**
     * Get XML options to use when saving XML
     * See: DOMDocument::saveXML
     * 
     * @return int
     */
    public function getXMLOptions()
    {
       return $this->xmlOptions;
    }

    /**
     * Get the array of allowed tags
     *
     * @return array
     */
    public function getAllowedTags()
    {
        return $this->allowedTags;
    }

    /**
     * Set custom allowed tags
     *
     * @param TagInterface $allowedTags
     */
    public function setAllowedTags(TagInterface $allowedTags)
    {
        $this->allowedTags = $allowedTags::getTags();
    }

    /**
     * Get the array of allowed attributes
     *
     * @return array
     */
    public function getAllowedAttrs()
    {
        return $this->allowedAttrs;
    }

    /**
     * Set custom allowed attributes
     *
     * @param AttributeInterface $allowedAttrs
     */
    public function setAllowedAttrs(AttributeInterface $allowedAttrs)
    {
        $this->allowedAttrs = $allowedAttrs::getAttributes();
    }

    /**
     * Should we remove references to remote files?
     *
     * @param bool $removeRemoteRefs
     */
    public function removeRemoteReferences($removeRemoteRefs = false)
    {
        $this->removeRemoteReferences = $removeRemoteRefs;
    }

    /**
     * Sanitize the passed string
     *
     * @param string $dirty
     * @return string
     */
    public function sanitize($dirty)
    {
        // Don't run on an empty string
        if (empty($dirty)) {
            return '';
        }

        // Strip php tags
        $dirty = preg_replace('/<\?(=|php)(.+?)\?>/i', '', $dirty);

        $this->resetInternal();
        $this->setUpBefore();

        $loaded = $this->xmlDocument->loadXML($dirty);

        // If we couldn't parse the XML then we go no further. Reset and return false
        if (!$loaded) {
            $this->resetAfter();
            return false;
        }

        $this->removeDoctype();

        // Grab all the elements
        $allElements = $this->xmlDocument->getElementsByTagName("*");

        // Start the cleaning proccess
        $this->startClean($allElements);

        // Save cleaned XML to a variable
        if ($this->removeXMLTag) {
            $clean = $this->xmlDocument->saveXML($this->xmlDocument->documentElement, $this->xmlOptions);
        } else {
            $clean = $this->xmlDocument->saveXML($this->xmlDocument, $this->xmlOptions);
        }

        $this->resetAfter();

        // Remove any extra whitespaces when minifying
        if ($this->minifyXML) {
            $clean = preg_replace('/\s+/', ' ', $clean);
        }

        // Return result
        return $clean;
    }

    /**
     * Set up libXML before we start
     */
    protected function setUpBefore()
    {
        // Turn off the entity loader
        $this->xmlLoaderValue = libxml_disable_entity_loader(true);

        // Suppress the errors because we don't really have to worry about formation before cleansing
        libxml_use_internal_errors(true);
    }

    /**
     * Reset the class after use
     */
    protected function resetAfter()
    {
        // Reset the entity loader
        libxml_disable_entity_loader($this->xmlLoaderValue);
    }

    /**
     * Remove the XML Doctype
     * It may be caught later on output but that seems to be buggy, so we need to make sure it's gone
     */
    protected function removeDoctype()
    {
        foreach ($this->xmlDocument->childNodes as $child) {
            if ($child->nodeType === XML_DOCUMENT_TYPE_NODE) {
                $child->parentNode->removeChild($child);
            }
        }
    }

    /**
     * Start the cleaning with tags, then we move onto attributes and hrefs later
     *
     * @param \DOMNodeList $elements
     */
    protected function startClean(\DOMNodeList $elements)
    {
        // loop through all elements
        // we do this backwards so we don't skip anything if we delete a node
        // see comments at: http://php.net/manual/en/class.domnamednodemap.php
        for ($i = $elements->length - 1; $i >= 0; $i--) {
            $currentElement = $elements->item($i);

            // If the tag isn't in the whitelist, remove it and continue with next iteration
            if (!in_array(strtolower($currentElement->tagName), $this->allowedTags)) {
                $currentElement->parentNode->removeChild($currentElement);
                continue;
            }

            $this->cleanAttributesOnWhitelist($currentElement);

            $this->cleanXlinkHrefs($currentElement);

            $this->cleanHrefs($currentElement);

            if (strtolower($currentElement->tagName) === 'use') {
                if ($this->isUseTagDirty($currentElement)) {
                    $currentElement->parentNode->removeChild($currentElement);
                    continue;
                }
            }
        }
    }

    /**
     * Only allow attributes that are on the whitelist
     *
     * @param \DOMElement $element
     */
    protected function cleanAttributesOnWhitelist(\DOMElement $element)
    {
        for ($x = $element->attributes->length - 1; $x >= 0; $x--) {
            // get attribute name
            $attrName = $element->attributes->item($x)->name;

            // Remove attribute if not in whitelist
            if (!in_array(strtolower($attrName), $this->allowedAttrs) && !$this->isAriaAttribute(strtolower($attrName)) && !$this->isDataAttribute(strtolower($attrName))) {
                $element->removeAttribute($attrName);
            }

            // Do we want to strip remote references?
            if($this->removeRemoteReferences) {
                // Remove attribute if it has a remote reference
                if (isset($element->attributes->item($x)->value) && $this->hasRemoteReference($element->attributes->item($x)->value)) {
                    $element->removeAttribute($attrName);
                }
            }
        }
    }

    /**
     * Clean the xlink:hrefs of script and data embeds
     *
     * @param \DOMElement $element
     */
    protected function cleanXlinkHrefs(\DOMElement $element)
    {
        $xlinks = $element->getAttributeNS('http://www.w3.org/1999/xlink', 'href');
        if (preg_match(self::SCRIPT_REGEX, $xlinks) === 1) {
            if (!in_array(substr($xlinks, 0, 14), array(
                'data:image/png', // PNG
                'data:image/gif', // GIF
                'data:image/jpg', // JPG
                'data:image/jpe', // JPEG
                'data:image/pjp', // PJPEG
            ))) {
                $element->removeAttributeNS( 'http://www.w3.org/1999/xlink', 'href' );
            }
        }
    }

    /**
     * Clean the hrefs of script and data embeds
     *
     * @param \DOMElement $element
     */
    protected function cleanHrefs(\DOMElement $element)
    {
        $href = $element->getAttribute('href');
        if (preg_match(self::SCRIPT_REGEX, $href) === 1) {
            $element->removeAttribute('href');
        }
    }

    /**
     * Removes non-printable ASCII characters from string & trims it
     *
     * @param string $value
     * @return bool
     */
    protected function removeNonPrintableCharacters($value)
    {
        return trim(preg_replace('/[^ -~]/xu','',$value));
    }

    /**
     * Does this attribute value have a remote reference?
     *
     * @param $value
     * @return bool
     */
    protected function hasRemoteReference($value)
    {
        $value = $this->removeNonPrintableCharacters($value);

        $wrapped_in_url = preg_match('~^url\(\s*[\'"]\s*(.*)\s*[\'"]\s*\)$~xi', $value, $match);
        if (!$wrapped_in_url){
            return false;
        }

        $value = trim($match[1], '\'"');

        return preg_match('~^((https?|ftp|file):)?//~xi', $value);
    }

    /**
     * Should we minify the output?
     *
     * @param bool $shouldMinify
     */
    public function minify($shouldMinify = false)
    {
        $this->minifyXML = (bool) $shouldMinify;
    }

    /**
     * Should we remove the XML tag in the header?
     *
     * @param bool $removeXMLTag
     */
    public function removeXMLTag($removeXMLTag = false)
    {
        $this->removeXMLTag = (bool) $removeXMLTag;
    }

    /**
     * Check to see if an attribute is an aria attribute or not
     *
     * @param $attributeName
     *
     * @return bool
     */
    protected function isAriaAttribute($attributeName)
    {
        return strpos($attributeName, 'aria-') === 0;
    }

    /**
     * Check to see if an attribute is an data attribute or not
     *
     * @param $attributeName
     *
     * @return bool
     */
    protected function isDataAttribute($attributeName)
    {
        return strpos($attributeName, 'data-') === 0;
    }

    /**
     * Make sure our use tag is only referencing internal resources
     *
     * @param \DOMElement $element
     * @return bool
     */
    protected function isUseTagDirty(\DOMElement $element)
    {
        $xlinks = $element->getAttributeNS('http://www.w3.org/1999/xlink', 'href');
        if ($xlinks && substr($xlinks, 0, 1) !== '#') {
            return true;
        }

        return false;
    }
}
