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
