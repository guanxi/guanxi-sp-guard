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
  const JSON_DELIM = "\" ";

  private $sessionID;
  private $samlResponse;
  private $attributes;

  /**
   * Constructor to build a Pod from JSON
   */
  public function __construct($json) {
    $inSessionID = false;
    $inSAMLResponse = false;
    $inAttributeName = false;
    $inAttributeValue = false;
    $attributeName = "";

    $token = strtok(stripcslashes($json), self::JSON_DELIM);
    while ($token !== false) {
      // We can ignore the first token as it just opens the JSON
      $token = strtok(self::JSON_DELIM);

      if (($token == " ") ||
          (stristr($token, "{")) ||
          (stristr($token, "}")) ||
          (stristr($token, "[")) ||
          (stristr($token, "]")) ||
          ($token == ",") ||
          ($token == ":")) {
        continue;
      }
      elseif ($token == "sessionID") {
        $inSessionID = true;
      }
      elseif ($token == "samlResponse") {
        $inSAMLResponse = true;
      }
      elseif ($token == "attributeName") {
        $inAttributeName = true;
      }
      elseif ($token == "attributeValue") {
        $inAttributeValue = true;
      }
      else {
        if ($inSessionID) {
          $this->sessionID = $token;
          $inSessionID = false;
        }
        if ($inSAMLResponse) {
          $this->samlResponse = base64_decode($token);
          $inSAMLResponse = false;
        }
        if ($inAttributeName) {
          $attributeName = $token;
          $inAttributeName = false;
        }
        if ($inAttributeValue) {
          $this->attributes[$attributeName] = $token;
          $inAttributeValue = false;
        }
      }
    }
  }

  /**
   * Returns the raw SAML Response from the IdP
   */
  public function getSAMLResponse() {
    return $this->samlResponse;
  }

  /**
   * Returns the session ID associated with the attributes
   */
  public function getSessionID() {
    return $this->sessionID;
  }

  /**
   * Returns an associative array containing the attribute names and values
   *
   * Returns:
   * [urn:test:id][harrymcd]
   */
  public function getAttributes() {
    return $this->attributes;
  }
}
?>
