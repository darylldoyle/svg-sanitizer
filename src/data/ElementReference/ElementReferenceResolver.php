<?php
namespace enshrined\svgSanitize\data;

class ElementReferenceResolver
{
    const DEFAULT_NAMESPACE_PREFIX = 'svg';

    /**
     * @var \DOMDocument
     */
    protected $document;

    /**
     * @var string
     */
    protected $defaultNamespaceURI;

    /**
     * @var ElementReference[]
     */
    protected $elementReferences = [];

    public function __construct(\DOMDocument $document)
    {
        $this->document = $document;
        $this->determineDefaultNamespace();
    }

    public function collect()
    {
        $this->collectIdentifiedElements();
        $this->processReferences();

        #foreach ($this->elementUsages as $elementUsage) {
            $el = $this->elementReferences['a9'];
            var_dump($el->getElement()->getAttribute('id'), $el->countTargetUsages());
        #}
    }

    protected function determineDefaultNamespace()
    {
        $svgElements = $this->document->getElementsByTagName('svg');
        if ($svgElements->length !== 1) {
            throw new \LogicException(
                sprintf('Got %d svg elements, expected exactly one', $svgElements->length),
                1570870568
            );
        }
        $this->defaultNamespaceURI = (string)$svgElements->item(0)->namespaceURI;
    }

    protected function collectIdentifiedElements()
    {
        $xpath = new \DOMXPath($this->document);
        /** @var \DOMNodeList|\DOMElement[] $elements */
        $elements = $xpath->query('//*[@id]');
        foreach ($elements as $element) {
            $this->elementReferences[$element->getAttribute('id')] = new ElementReference($element);
        }
    }

    protected function processReferences()
    {
        $xpath = $this->createXPath();
        foreach ($this->elementReferences as $elementReference) {
            $useElements = $xpath->query(
                $this->createNodeName('use') . '[@href or @xlink:href]',
                $elementReference->getElement()
            );
            /** @var \DOMElement $useElement */
            foreach ($useElements as $useElement) {
                $useId = null;
                if ($useElement->hasAttribute('href')) {
                    $useId = $this->determineIdReference(
                        $useElement->getAttribute('href')
                    );
                } elseif ($useElement->hasAttribute('xlink:href')) {
                    $useId = $this->determineIdReference(
                        $useElement->getAttribute('xlink:href')
                    );
                }
                if ($useId === null || !isset($this->elementReferences[$useId])) {
                    continue;
                }
                $elementReference->uses($this->elementReferences[$useId]);
                $this->elementReferences[$useId]->usedIn($elementReference);
            }
        }
    }

    protected function determineIdReference(string $href)
    {
        if (strpos($href, '#') === 0) {
            return substr($href, 1);
        }
        return null;
    }

    protected function createNodeName(string $nodeName)
    {
        if (empty($this->defaultNamespaceURI)) {
            return $nodeName;
        }
        return self::DEFAULT_NAMESPACE_PREFIX . ':' . $nodeName;
    }

    protected function createXPath()
    {
        $xpath = new \DOMXPath($this->document);
        if (!empty($this->defaultNamespaceURI)) {
            $xpath->registerNamespace(self::DEFAULT_NAMESPACE_PREFIX, $this->defaultNamespaceURI);
        }
        return $xpath;
    }
}