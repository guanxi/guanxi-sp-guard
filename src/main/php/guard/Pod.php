<?php
/*
//: "The contents of this file are subject to the Mozilla Public License
//: Version 1.1 (the "License"); you may not use this file except in
//: compliance with the License. You may obtain a copy of the License at
//: http://www.mozilla.org/MPL/
//:
//: Software distributed under the License is distributed on an "AS IS"
//: basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//: License for the specific language governing rights and limitations
//: under the License.
//:
//: The Original Code is Guanxi (http://www.guanxi.uhi.ac.uk).
//:
//: The Initial Developer of the Original Code is Alistair Young alistair@codebrane.com
//: All Rights Reserved.
//:
*/

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
