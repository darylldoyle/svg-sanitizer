<?php
namespace enshrined\svgSanitize\ElementReference;

class Subject
{
    const TAG_INVALID = 1;
    const TAG_SELF_REFERENCE = 2;
    const TAG_INFINITE_LOOP = 3;

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
     * @var int[]
     */
    protected $tags = [];

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
     * @param array $subjects Previously processed subjects
     * @return bool
     */
    public function hasInfiniteLoop(array $subjects = [])
    {
        if (in_array($this, $subjects, true)) {
            return true;
        }
        $subjects[] = $this;
        foreach ($this->useCollection as $usage) {
            if ($usage->getSubject()->hasInfiniteLoop($subjects)) {
                return true;
            }
        }
        return false;
    }

    /**
     * @param int[] $tags (see Subject constants)
     */
    public function addTags(array $tags)
    {
        $tags = array_map('intval', $tags);
        $this->tags = array_merge($this->tags, array_diff($tags, $this->tags));
    }

    /**
     * @param int[] $tags (see Subject constants)
     * @return bool
     */
    public function matchesTags(array $tags)
    {
        $amount = count($tags);
        return $amount > 0 && count(array_intersect($this->tags, $tags)) === $amount;
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