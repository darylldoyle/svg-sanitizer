<?php
namespace enshrined\svgSanitize\data;

class ElementReference
{
    /**
     * @var \DOMElement
     */
    protected $element;

    /**
     * @var ElementReference[]
     */
    protected $targetUsages = [];

    /**
     * @var ElementReference[]
     */
    protected $fromUsages = [];

    /**
     * @param \DOMElement $element
     */
    public function __construct(\DOMElement $element)
    {
        $this->element = $element;
    }

    /**
     * @return \DOMElement
     */
    public function getElement()
    {
        return $this->element;
    }

    /**
     * @return string
     */
    public function getElementId()
    {
        return $this->element->getAttribute('id');
    }

    public function uses(ElementReference $usage)
    {
        if ($usage === $this) {
            throw new \LogicException('Cannot add self as usage', 1570713416);
        }
        if (in_array($usage, $this->targetUsages, true)) {
            return;
        }
        $this->targetUsages[] = $usage;
    }

    public function usedIn(ElementReference $usage)
    {
        if ($usage === $this) {
            throw new \LogicException('Cannot add self as usage', 1570713417);
        }
        if (in_array($usage, $this->fromUsages, true)) {
            return;
        }
        $this->fromUsages[] = $usage;
    }

    /**
     * @return int
     */
    public function countTargetUsages()
    {
        $count = 0;
        foreach ($this->targetUsages as $targetUsage) {
            $count += 1 + $targetUsage->countTargetUsages();
        }
        return $count;
    }

    /**
     * @param string $query
     * @return \DOMNodeList|\DOMElement[]
     */
    public function query(string $query)
    {
        $xpath = new \DOMXPath($this->element->ownerDocument);
        return $xpath->query($query, $this->element);
    }
}