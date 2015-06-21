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
     *
     */
    function __construct()
    {
        $this->resetInternal();

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
        $this->xmlDocument->preserveWhiteSpace = true;
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
     * Set custom allowed attributes
     *
     * @param AttributeInterface $allowedAttrs
     */
    public function setAllowedAttrs(AttributeInterface $allowedAttrs)
    {
        $this->allowedAttrs = $allowedAttrs::getAttributes();
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
     * Get the array of allowed attributes
     *
     * @return array
     */
    public function getAllowedAttrs()
    {
        return $this->allowedAttrs;
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

        // Turn off the entity loader
        $this->xmlLoaderValue = libxml_disable_entity_loader(true);

        // Suppress the errors because we don't really have to worry about formation before cleansing
        @$this->xmlDocument->loadXML($dirty);

        // We're using this loop to remove the XML Doctype
        // Whilst it may be caught below on output, that seems to be buggy, so we need to make sure it's gone
        foreach ($this->xmlDocument->childNodes as $child) {
            if ($child->nodeType === XML_DOCUMENT_TYPE_NODE) {
                $child->parentNode->removeChild($child);
            }
        }

        // Grab all the elements
        $allElements = $this->xmlDocument->getElementsByTagName("*");

        // loop through all elements
        // we do this backwards so we don't skip anything if we delete a node
        // see comments at: http://php.net/manual/en/class.domnamednodemap.php
        for ($i = $allElements->length - 1; $i >= 0; $i--) {
            $currentElement = $allElements->item($i);

            // If the tag isn't in the whitelist, remove it and continue with next iteration
            if (!in_array($currentElement->tagName, $this->allowedTags)) {
                $currentElement->parentNode->removeChild($currentElement);
                continue;
            }

            // loop through all attributes, see above for reason we go backwards
            for ($x = $currentElement->attributes->length - 1; $x >= 0; $x--) {
                // get attribute name
                $attrName = $currentElement->attributes->item($x)->name;

                // Remove attribute if not in whitelist
                if (!in_array($attrName, $this->allowedAttrs)) {
                    $currentElement->removeAttribute($attrName);
                }
            }
        }

        // Save cleaned XML to a variable
        $clean = $this->xmlDocument->saveXML($this->xmlDocument->documentElement);

        // Reset DOMDocument to a clean state in case we use it again
        $this->resetInternal();

        // Reset the entity loader3
        libxml_disable_entity_loader($this->xmlLoaderValue);

        // Return result
        return $clean;
    }
}