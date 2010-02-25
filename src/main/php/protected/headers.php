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
 * headers.jsp
 *
 * Displays the attributes and raw SAML Response
 *
 * To access using Shibboleth:
 * https://your.site.com/protected/
 *
 * To access using SAML2 Web Browser SSO:
 * https://your.site.com/protected?entityID=IDP_ENTITY_ID
 */

include "guanxi_sp_guard/config.php";
require_once "guanxi_sp_guard/utils.php";

session_start();

$sessionData = loadSession($_SESSION[SESSION_VAR_SESSION_ID]);

if ($_POST[mode] == "logout") {
  destroySession($sessionData[SESSION_VAR_SESSION_ID]);
  unset($_SESSION[SESSION_VAR_SESSION_ID]);
  echo "<p><center><strong>Your are logged out of the SP!</strong></center></p>";
  return;
}

if (!empty($sessionData[SESSION_VAR_ATTRIBUTES])) {
  foreach (array_keys($sessionData[SESSION_VAR_ATTRIBUTES]) as $key) {
    echo $key." = ".htmlspecialchars($sessionData[SESSION_VAR_ATTRIBUTES][$key])."<br />";
  }
}
else {
  echo "No attributes available from the IdP";
}
?>
<p>
  <form method="post" action="">
    <input type="submit" name="submit" value="Logout" />
    <input type="hidden" name="mode" value="logout" />
  </form>
</p>
<? echo "<br />SAML Response from the IdP:<br />"; ?>
<textarea rows='40' cols='150'>
<? echo $sessionData[SESSION_VAR_SAML_RESPONSE]; ?>
</textarea>
