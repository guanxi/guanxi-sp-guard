<?php
/**
 * Guanxi Guard for Elgg
 * http://elgg.org/
 */
 
// Guanxi dependencies
include "config.php";
require_once "utils.php";

// Elgg dependencies
require_once("../config.php");
require_once('../lib/cache/lib.php');
require_once('../lib/datalib.php');
require_once('../lib/elgglib.php');
require_once('../lib/constants.php');
require_once('../lib/setup.php');
require_once("../includes_system.php");
require_once('../lib/userlib.php');
require_once('../lib/dbsetup.php');

session_start();

$userInfo = mapShibbToElggUser(loadSession($_SESSION[SESSION_VAR_SESSION_ID]));

if (!createElggUser($userInfo)) {
	echo "login error!";
}
else {
	/* The Guard's job is now finished. We redirected to a shibboleth SSO endpoint,
	 * got the attributes and logged the user into Elgg. From now on it's Elgg's
	 * job to control them.
	 * We should now delete the Guanxi session and let Elgg control logout.
	 */
 	destroySession($sessionData[SESSION_VAR_SESSION_ID]);
	unset($_SESSION[SESSION_VAR_SESSION_ID]);

	header("Location: ".$CFG->wwwroot);
}


function mapShibbToElggUser($sessionData) {
	foreach (array_keys($sessionData[SESSION_VAR_ATTRIBUTES]) as $key) {
		if ($key == "urn:mace:dir:attribute-def:eduPersonPrincipalName") {
			// Chuck out the domain
			$parts = explode("@", $sessionData[SESSION_VAR_ATTRIBUTES][$key]);
			$sessionData[SESSION_VAR_ATTRIBUTES][$key] = $parts[0];
		}
		
		$userInfo[$key] = $sessionData[SESSION_VAR_ATTRIBUTES][$key];
	}
	
	return $userInfo;
}

function createElggUser($userInfo) {
	if (!preg_match("/^[A-Za-z0-9.\-]{3,20}$/", $userInfo['urn:mace:dir:attribute-def:eduPersonPrincipalName'])) {
		echo __gettext("Error! LDAP Username does not meet Elgg requirements");
	  return false;
	}
 	else {
		// Does the user already exist?
		$username = strtolower($userInfo['urn:mace:dir:attribute-def:eduPersonPrincipalName']);

    if (record_exists('users', 'username', $username)) {
    	// User exists so load it from the database
    	$user = get_record("users", "username", $username);
    }
    else {
			// Create the new user
			$user = new StdClass;
			$user->email = $userInfo["urn:mace:dir:attribute-def:mail"];
			$user->name  = $userInfo["urn:mace:dir:attribute-def:givenName"];
			$user->name  = $user->name . " " . $userInfo["urn:mace:dir:attribute-def:sn"];
			$user->username = $username;
			$user->password = md5(md5(uniqid(rand(), true)));
			$user->user_type = 'person';
			$user->owner = -1;
			
      $user->ident = insert_record('users', $user);

      if (!empty($user->ident)) {
	    	$rssresult = run("weblogs:rss:publish", array($user->ident, false));
	      $rssresult = run("files:rss:publish", array($user->ident, false));
	      $rssresult = run("profile:rss:publish", array($user->ident, false));
      }
      else {
      	// User creation failed
        echo sprintf(__gettext("User addition %d failed: Unknown reason, please contact you system administrator."), $username);
        return false;
      }
    }
  }
  
  return loginUser($user);
}

function loginUser($user) {
	global $CFG;
	
	$id = (int)$user->ident;
  if(!$id) {
  	return false;
  }
   
  // Double MD5
  if (!defined("SECRET_SALT")) {
  	define("SECRET_SALT", "SECRET_SALT");
  }
  $ticket = md5(SECRET_SALT . $id . time());
  $md5ticket = md5($ticket);
   
  // Update MD5 of authticket
  $user->code = $md5ticket;
  $user->ident = $id;
  update_record('users', $user);
   
  setcookie(AUTH_COOKIE, $ticket, time()+AUTH_COOKIE_LENGTH, $CFG->cookiepath);
  global $messages;
  $messages[] = __gettext("The system will remember you and automatically log you in next time.");
   
  return true;
}

?>

