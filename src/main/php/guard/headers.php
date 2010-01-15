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

include "config.php";
require_once "utils.php";

session_start();

$sessionData = loadSession($_SESSION[SESSION_VAR_SESSION_ID]);

if ($_POST[mode] == "logout") {
	destroySession($sessionData[SESSION_VAR_SESSION_ID]);
	unset($_SESSION[SESSION_VAR_SESSION_ID]);
	echo "<p><center><strong>Your are logged out of the SP!</strong></center></p>";
	return;
}

foreach (array_keys($sessionData[SESSION_VAR_ATTRIBUTES]) as $key) {
	echo $key." = ".htmlspecialchars($sessionData[SESSION_VAR_ATTRIBUTES][$key])."<br />";
}
?>
<p>
	<form method="post" action="">
		<input type="submit" name="submit" value="Logout" />
		<input type="hidden" name="mode" value="logout" />
	</form>
</p>
