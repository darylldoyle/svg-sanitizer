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
     * @var int
     */
    protected $useNestingLimit;

    /**
     * Number of subjects on the longest chain of uses starting here, once this
     * subject is known to lead to no loop. Null until then.
     *
     * Remembering it means each subject is walked once. Without it, a layered
     * graph where every element uses every element of the next layer was walked
     * once per path, and the number of paths grows exponentially with depth.
     *
     * @var int|null
     */
    protected $loopFreeDepth;

    /**
     * Results of countUse(), keyed by its $accumulated argument.
     *
     * @var array<int, int>
     */
    protected $useCounts = [];

    /**
     * @var bool
     */
    protected $countingUse = false;

    /**
     * Subject constructor.
     *
     * @param \DOMElement $element
     * @param int         $useNestingLimit
     */
    public function __construct(\DOMElement $element, $useNestingLimit)
    {
        $this->element = $element;
        $this->useNestingLimit = $useNestingLimit;
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
     * @param array $subjects   Previously processed subjects
     * @param int   $level      The current level of nesting.
     * @return bool
     * @throws \enshrined\svgSanitize\Exceptions\NestingException
     */
    public function hasInfiniteLoop(array $subjects = [], $level = 1)
    {
        if ($level > $this->useNestingLimit) {
            throw new \enshrined\svgSanitize\Exceptions\NestingException('Nesting level too high, aborting', 1570713498, null, $this->getElement());
        }

        if (in_array($this, $subjects, true)) {
            return true;
        }

        // Already known to lead to no loop: only the nesting limit still depends
        // on the level we reached this subject at. If the known chain would go
        // past the limit, walk again so the exception names the right element.
        if ($this->loopFreeDepth !== null && $level + $this->loopFreeDepth - 1 <= $this->useNestingLimit) {
            return false;
        }

        $subjects[] = $this;
        $depth = 1;
        foreach ($this->useCollection as $usage) {
            $usedSubject = $usage->getSubject();
            if ($usedSubject->hasInfiniteLoop($subjects, $level + 1)) {
                return true;
            }
            $depth = max($depth, 1 + $usedSubject->loopFreeDepth);
        }
        $this->loopFreeDepth = $depth;

        return false;
    }

    /**
     * @param Subject $subject
     */
    public function addUse(Subject $subject)
    {
        if ($subject === $this) {
            throw new \LogicException('Cannot add self usage', 1570713416);
        }
        $this->forgetComputedValues();
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
        $key = $accumulated ? 1 : 0;
        if (isset($this->useCounts[$key])) {
            return $this->useCounts[$key];
        }

        // Reached again while still counting: a reference loop. Loops are found
        // and removed by hasInfiniteLoop(), so count nothing rather than recurse
        // forever.
        if ($this->countingUse) {
            return 0;
        }

        $this->countingUse = true;
        $count = 0;
        foreach ($this->useCollection as $use) {
            $useCount = $use->getSubject()->countUse();
            $count += $use->getCount() * ($accumulated ? 1 + $useCount : max(1, $useCount));
            // Stop at the largest integer instead of overflowing into a float.
            if (!is_int($count)) {
                $count = PHP_INT_MAX;
                break;
            }
        }
        $this->countingUse = false;

        return $this->useCounts[$key] = $count;
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

    /**
     * Clear the internal arrays (to free up memory as they can get big)
     * and return all the child usages DOMElement's
     *
     * @return array
     */
    public function clearInternalAndGetAffectedElements()
    {
        $elements = array_map(function(Usage $usage) {
            return $usage->getSubject()->getElement();
        }, $this->useCollection);

        $this->usedInCollection = [];
        $this->useCollection = [];
        $this->forgetComputedValues();

        return $elements;
    }

    /**
     * Drop remembered results after this subject's own uses change.
     */
    protected function forgetComputedValues()
    {
        $this->loopFreeDepth = null;
        $this->useCounts = [];
    }
}