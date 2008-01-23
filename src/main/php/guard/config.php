<?php
/**
 * Guanxi PHP Guard configuration file.
 * 
 * Full documentation can be found on the Guanxi wiki:
 * http://www.guanxi.uhi.ac.uk/index.php/PHP_Guard
 *
 * Don't forget to modify .htaccess too!
 */
 
/** The ID of this Guard. This must be registered with the appropriate Guanxi Engine */
define(GUARD_ID, "sgarbh-phpguard");
/** The URL of the Engine's WAYF Location Service */
define(ENGINE_WAYF_LOCATION_SERVICE, "http://sgarbh.smo.uhi.ac.uk:8080/samlengine/engine.guanxiWAYFLocation");
/** The URL of the Engine's Authentication Consumer Service */
define(ENGINE_AUTH_CONSUMER_SERVICE, "http://sgarbh.smo.uhi.ac.uk:8080/samlengine/engine.guanxiEngineAuthCS");
/** Where the sessions are to be created. This directory must be writeable to the web server. */
define(SESSION_IDS_DIR, "sessions/");
/** The path for the session cookie */
define(COOKIE_PATH, "/");
/** The lifetime for the session cookie in milliseconds. -1 means a transient cookie which will disappear
  * when the browser is closed. */
define(COOKIE_LIFETIME, "-1");

// -----------------------------------------------------------------------------------------
// DO NOT EDIT BELOW THIS LINE

/** The index in the session data of the session ID */
define(SESSION_VAR_SESSION_ID, "id");
/** The index in the session data of the originally requested page's URL, e.g. /gxrest/headers.php */
define(SESSION_VAR_URL, "url");
/** The index in the session data of the marker that denotes whether the session has be authorised.
    The Attribute Consumer Service sets this based on attributes it gets from the Engine. */
define(SESSION_VAR_AUTHZ, "authz");
/** The index in the session data of the value of the SESSION_VAR_AUTHZ marker */
define(SESSION_VAR_AUTHZ_VALUE, "authzed");
/** The index in the session data of the raw SAML, containing the attributes, from the Engine */
define(SESSION_VAR_RAW_ATTRIBUTES, "rawattributes");
/** The index in the session data of the associative array of the parsed attribute names and values */
define(SESSION_VAR_ATTRIBUTES, "attributes");

/** The value to return to the Engine from the Session Verifier Service is a session has been verified */
define(SESSION_VERIFIED, "verified");
/** The value to return to the Engine from the Session Verifier Service is a session has not been verified */
define(SESSION_NOT_VERIFIED, "notverified");
?>
