<?php
/**
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
$pod = new Pod($GLOBALS['HTTP_RAW_POST_DATA']);

// Load up the current session
$sessionData = loadSession($pod->getSessionID());

// Mark the session as having been authorised, i.e. it has attributes
$sessionData[SESSION_VAR_AUTHZ] = SESSION_VAR_AUTHZ_VALUE;

// Store the raw SAML in the session in case anything wants to use it
$sessionData[SESSION_VAR_RAW_ATTRIBUTES] = $GLOBALS['HTTP_RAW_POST_DATA'];

// Store the associative array of attribute names and values in the session
$sessionData[SESSION_VAR_ATTRIBUTES] = $pod->getAttributes();

// Save the updated session
saveSession($sessionData);

// Return the SOAP response to the Engine
echo "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">";
echo "<soapenv:Body>";
echo "</soapenv:Body>";
echo "</soapenv:Envelope>";
?>
