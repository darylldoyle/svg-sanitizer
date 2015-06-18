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
        $this->xmlDocument->loadHTML($dirty);

        $allElements = $this->xmlDocument->getElementsByTagName("*");

        $this->resetInternal();

        return $allElements;
    }
}