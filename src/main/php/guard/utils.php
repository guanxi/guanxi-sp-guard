<?php
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
