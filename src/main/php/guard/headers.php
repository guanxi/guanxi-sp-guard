<?php
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
