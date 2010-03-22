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
 * GuanxiAttributeConsumerService.php
 *
 * Attribute Consumer Service.
 *
 * This service is responsible for parsing the SAML response that is issued by an IdP in reply to
 * a SAML AttributeQuery. The SAML response is sent here by the Engine.
 *
 * For this service to work, the following setting must be enabled in either php.ini or .htaccess:
 * always_populate_raw_post_data
 */

include "config.php";
include "Pod.php";

// Get a new Pod ready
$pod = new Pod($HTTP_POST_VARS['REQUEST_PARAMETER_SAML_ATTRIBUTES']);

// Load up the current session
$sessionData = loadSession($pod->getSessionID());

// Mark the session as having been authorised, i.e. it has attributes
$sessionData[SESSION_VAR_AUTHZ] = SESSION_VAR_AUTHZ_VALUE;

// Store the SAML Response in the session in case anything wants to use it
$sessionData[SESSION_VAR_SAML_RESPONSE] = $pod->getSAMLResponse();

// Store the associative array of attribute names and values in the session
$sessionData[SESSION_VAR_ATTRIBUTES] = $pod->getAttributes();

// Save the updated session
saveSession($sessionData);

// Return the response to the Engine
echo "OK";
?>
