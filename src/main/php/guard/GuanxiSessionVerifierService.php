<?php
/**
 * Session Verifier Service.
 *
 * This service is responsible for answering queries by an Engine for a session to be verified.
 * The GuanxiGuard will create a new session for each new user and register it with PHP's session
 * mechanism. The session ID of this new session is sent to the Engine as part of the WAYF location
 * discovery process and the Engine will call this service with the session ID, to make sure this
 * Guard did indeed create the session.
 */
 
include "config.php";
require_once "utils.php";

if (isSession($_GET[sessionid]))
	echo SESSION_VERIFIED;
else
	echo SESSION_NOT_VERIFIED;
?>
