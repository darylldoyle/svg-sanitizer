<?php
namespace enshrined\svgSanitize\ElementReference;

use enshrined\svgSanitize\data\XPath;
use enshrined\svgSanitize\Helper;

class Resolver
{
    /**
     * @var XPath
     */
    protected $xPath;

    /**
     * @var Subject[]
     */
    protected $subjects = [];

    public function __construct(XPath $xPath)
    {
        $this->xPath = $xPath;
    }

    public function collect()
    {
        $this->collectIdentifiedElements();
        $this->processReferences();
    }

    /**
     * Resolves elements (plural!) by element id - in theory malformed
     * DOM might have same ids assigned to different elements and leaving
     * it to client/browser implementation which element to actually use.
     *
     * @param string $elementId
     * @return Subject[]
     */
    public function findByElementId($elementId)
    {
        return array_filter(
            $this->subjects,
            function (Subject $subject) use ($elementId) {
                return $elementId === $subject->getElementId();
            }
        );
    }

    protected function collectIdentifiedElements()
    {
        /** @var \DOMNodeList|\DOMElement[] $elements */
        $elements = $this->xPath->query('//*[@id]');
        foreach ($elements as $element) {
            $this->subjects[$element->getAttribute('id')] = new Subject($element);
        }
    }

    protected function processReferences()
    {
        $useNodeName = $this->xPath->createNodeName('use');
        foreach ($this->subjects as $elementReference) {
            $useElements = $this->xPath->query(
                $useNodeName . '[@href or @xlink:href]',
                $elementReference->getElement()
            );
            /** @var \DOMElement $useElement */
            foreach ($useElements as $useElement) {
                $useId = null;
                $useId = Helper::extractIdReferenceFromHref(
                    Helper::getElementHref($useElement)
                );
                if ($useId === null || !isset($this->subjects[$useId])) {
                    continue;
                }
                $elementReference->addUse($this->subjects[$useId]);
                $this->subjects[$useId]->addUsedIn($elementReference);
            }
        }
    }
}