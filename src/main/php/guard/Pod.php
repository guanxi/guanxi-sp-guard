<?php
/**
 * Pod
 *
 * This class handles all SAML processing for the Guanxi Guard and its modules.
 */
 
class Pod {
	const SAML_NS = "urn:oasis:names:tc:SAML:1.0:assertion";
	const SAMLP_NS = "urn:oasis:names:tc:SAML:1.0:protocol";
	
	private $doc;
	
	public function __construct($xmlDocAsString) {
		$this->doc = new DOMDocument();
		$this->doc->loadXML($xmlDocAsString);
	}
	
	public function dumpXML() {
		$this->doc->save("/Users/alistair/web/htdocs/gxrest/xml.txt");
	}
	
	/**
	 *
	 * <Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">
	 *   <Header>
	 *     <urn:GuanxiGuardSessionID xmlns:urn="urn:guanxi:sp">7539886c83fafaa5595c30bbeb4d916f</urn:GuanxiGuardSessionID>
	 *
	 */
	public function getSessionID() {
		$guanxiGuardSessionIDNode = $this->doc->getElementsByTagName("GuanxiGuardSessionID")->item(0);
		return $guanxiGuardSessionIDNode->nodeValue;
	}
	
	/**
	 * Returns an associative array containing the attribute names and values
	 * extracted from the SAML:
	 *
	 * <Attribute AttributeName="urn:test:id"
	 *					  AttributeNamespace="urn:mace:shibboleth:1.0:attributeNamespace:uri">
	 *   <AttributeValue>harrymcd</AttributeValue>
	 * </Attribute>
	 *
	 * Returns:
	 * [urn:test:id][harrymcd]
	 */
	public function getAttributes() {
		foreach ($this->doc->getElementsByTagName("Attribute") as $attributeNode) {
			$attributes = $attributeNode->attributes;
			
			$attributeName = $attributes->getNamedItem("AttributeName")->nodeValue;
			foreach ($attributeNode->childNodes as $childNode) {
				if ($childNode->localName == "AttributeValue") {
					$attributeValue = $childNode->nodeValue;
				}
			}
			
			$attributeNamesAndValues[$attributeName] = $attributeValue;
		}
		
		return $attributeNamesAndValues;
	}
}
?>
