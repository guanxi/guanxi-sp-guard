<?php
/**
 * Podder Service.
 *
 * This service is responsible for redirecting to the originally requested page.
 * By the time this service is called by the Engine, the attributes will have been processed
 * and a decision made by the Attribute Consumer Service and any policy services linked to it.
 */
 
include "config.php";

session_start();

// Redirect to the originally requested page
header("Location: ".$_SESSION[SESSION_VAR_URL]);
?>
