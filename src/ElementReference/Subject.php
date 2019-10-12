<?php
namespace enshrined\svgSanitize\ElementReference;

class Subject
{
    /**
     * @var \DOMElement
     */
    protected $element;

    /**
     * @var Usage[]
     */
    protected $useCollection = [];

    /**
     * @var Usage[]
     */
    protected $usedInCollection = [];

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

    /**
     * @param Subject $subject
     */
    public function addUse(Subject $subject)
    {
        if ($subject === $this) {
            throw new \LogicException('Cannot add self usage', 1570713416);
        }
        $identifier = $subject->getElementId();
        if (isset($this->useCollection[$identifier])) {
            $this->useCollection[$identifier]->increment();
            return;
        }
        $this->useCollection[$identifier] = new Usage($subject);
    }

    /**
     * @param Subject $subject
     */
    public function addUsedIn(Subject $subject)
    {
        if ($subject === $this) {
            throw new \LogicException('Cannot add self as usage', 1570713417);
        }
        $identifier = $subject->getElementId();
        if (isset($this->usedInCollection[$identifier])) {
            $this->usedInCollection[$identifier]->increment();
            return;
        }
        $this->usedInCollection[$identifier] = new Usage($subject);
    }

    /**
     * @param bool $accumulated
     * @return int
     */
    public function countUse($accumulated = false)
    {
        $count = 0;
        foreach ($this->useCollection as $use) {
            $useCount = $use->getSubject()->countUse();
            $count += $use->getCount() * ($accumulated ? 1 + $useCount : max(1, $useCount));
        }
        return $count;
    }

    /**
     * @return int
     */
    public function countUsedIn()
    {
        $count = 0;
        foreach ($this->usedInCollection as $usedIn) {
            $count += $usedIn->getCount() * max(1, $usedIn->getSubject()->countUsedIn());
        }
        return $count;
    }
}