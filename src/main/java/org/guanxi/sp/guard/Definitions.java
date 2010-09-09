package org.guanxi.sp.guard;

public class Definitions {
  /** The servlet context attribute that holds the Guard's config object */
  public static final String CONTEXT_ATTR_GUARD_CONFIG = "CONTEXT_ATTR_GUARD_CONFIG";
  /** The servlet context attribute that holds the ID of that webapp's Guard */
  public static final String CONTEXT_ATTR_GUARD_ID = "CONTEXT_ATTR_GUARD_ID";
  /** The servlet context attribute that holds the Guard's cookie prefix */
  public static final String CONTEXT_ATTR_GUARD_COOKIE_PREFIX = "CONTEXT_ATTR_GUARD_COOKIE_PREFIX";
  /** The servlet context attribute that holds the full cookie name that webapp's Guard */
  public static final String CONTEXT_ATTR_GUARD_COOKIE_NAME = "CONTEXT_ATTR_GUARD_COOKIE_NAME";
  /** The Guard ID request parameter for WAYFLocation service */
  public static final String WAYF_PARAM_GUARD_ID = "guardid";
  /** The Guard Session ID request parameter for WAYFLocation service */
  public static final String WAYF_PARAM_SESSION_ID = "sessionid";
  /** The Guard Session ID request parameter for SessionVerifier service */
  public static final String SESSION_VERIFIER_PARAM_SESSION_ID = "sessionid";
  /** SessionVerifier return value indicating session was verified */
  public static final String SESSION_VERIFIER_RETURN_VERIFIED = "verified";
  /** SessionVerifier return value indicating session was not verified */
  public static final String SESSION_VERIFIER_RETURN_NOT_VERIFIED = "notverified";
  /** The name of the request parameter that the Engine and Guard use to add and retrieve the
   *  SAML attributes when the Engine POSTs them to the Guard.
   */
  public static final String REQUEST_PARAMETER_SAML_ATTRIBUTES = "REQUEST_PARAMETER_SAML_ATTRIBUTES";
}
