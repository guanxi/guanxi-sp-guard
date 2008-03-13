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
 * utils
 *
 * Utility functions to support the Guard infrastructure
 */
 
include "config.php";

function getServiceName($requestURI) {
  $parts = split("/", $requestURI);
  $length = count($parts);
  $serviceName = $parts[$length - 1];
  if (stristr($serviceName, "?")) {
    $parts = split("\?", $serviceName);
    $serviceName = $parts[0];
  }
  return $serviceName;
}

function saveSession($sessionData) {
	$fd = fopen(SESSION_IDS_DIR.$sessionData[SESSION_VAR_SESSION_ID], "w+");
	fwrite($fd, serialize($sessionData));
	fclose($fd);
}

function isSession($sessionID) {
	return file_exists(SESSION_IDS_DIR.$sessionID);
}

function loadSession($sessionID) {
	$sessionFile = SESSION_IDS_DIR.$sessionID;
	
	if (file_exists($sessionFile)) {
		$fd = fopen($sessionFile, "r");
		if ($fd != null) {
  		$sessionData = unserialize(fread($fd, filesize($sessionFile)));
  		fclose ($fd);
  	}
  }
  
  return $sessionData;
}

function destroySession($sessionID) {
	$sessionFile = SESSION_IDS_DIR.$sessionID;
	
	if (file_exists($sessionFile)) {
		unlink($sessionFile);
	}
}

function debug($message) {
	$fd = fopen("debug", "a+");
	fwrite($fd, $message."\n");
	fclose($fd);
}
?>
