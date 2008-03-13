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
