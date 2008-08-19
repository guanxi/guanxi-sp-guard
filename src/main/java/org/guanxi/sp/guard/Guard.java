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

package org.guanxi.sp.guard;

import org.guanxi.common.definitions.Guanxi;
import org.guanxi.common.filters.FileName;
import org.guanxi.common.*;
import org.guanxi.common.security.SecUtils;
import org.guanxi.xal.sp.GuardDocument;
import org.apache.log4j.Logger;
import org.apache.xmlbeans.XmlOptions;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.servlet.*;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.Cookie;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.Provider;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * <font size=5><b></b></font>
 *
 * @author Alistair Young alistair@smo.uhi.ac.uk
 */
public class Guard implements Filter {
  /** 
   * Our logger 
   */
  private static final Logger logger = Logger.getLogger(Guard.class.getName());
  /** 
   * The name of the web.xml init-param that holds the location of the config file 
   */
  private static final String CONFIG_FILE_PARAM = "configFile";
  /** 
   * This Filter's config object as set by the container 
   */
  private static FilterConfig filterConfig = null;
  /** 
   * Indicates if we can unload the BouncyCastle security provider 
   */
  private boolean okToUnloadBCProvider = false;
  /**
   * This is the prefix for the headers that will hold attributes
   */
  private static String attributePrefix;

  public void init(FilterConfig config) throws ServletException {
    GuardDocument guardDoc;
    File keyStoreFile, trustStoreFile;
    
    // Store the config for later
    filterConfig = config;

    try {
      /* If we try to add the BouncyCastle provider but another Guanxi::Guard running
       * in another webapp in the same container has already done so, then we'll get
       * -1 returned from the method, in which case, we should leave unloading of the
       * provider to the particular Guanxi::Guard that loaded it.
       */
      if ((Security.addProvider(new BouncyCastleProvider())) != -1) {
        // We've loaded it, so we should unload it
        okToUnloadBCProvider = true;
      }

      // Load up the config file...
      guardDoc = GuardDocument.Factory.parse(new File(filterConfig.getServletContext().getRealPath(config.getInitParameter(CONFIG_FILE_PARAM))));

      // Sort out any config options that can be done automatically
      initConfigFile(config, guardDoc);

      // Make the config available to the rest of the Guard as an XMLBeans Guard object
      filterConfig.getServletContext().setAttribute(Guanxi.CONTEXT_ATTR_GUARD_CONFIG,
                                                    guardDoc.getGuard());

      /* Register our ID and cookie details in the servlet context
       * to allow applications to know who their Guard is.
       */
      filterConfig.getServletContext().setAttribute(Guanxi.CONTEXT_ATTR_GUARD_ID,
                                                    guardDoc.getGuard().getGuardInfo().getID());
      filterConfig.getServletContext().setAttribute(Guanxi.CONTEXT_ATTR_GUARD_COOKIE_PREFIX,
                                                    guardDoc.getGuard().getCookie().getPrefix());
      filterConfig.getServletContext().setAttribute(Guanxi.CONTEXT_ATTR_GUARD_COOKIE_NAME,
                                                    guardDoc.getGuard().getCookie().getPrefix() + guardDoc.getGuard().getGuardInfo().getID());

      attributePrefix = guardDoc.getGuard().getGuardInfo().getAttributePrefix();
      
      /* If we don't have a keystore, create a self signed one now. The keystore will hold
       * our private key and public key certificate in case we need to communicate with an
       * Engine's services via HTTPS.
       */
      keyStoreFile = new File(guardDoc.getGuard().getKeystore());
      if (!keyStoreFile.exists()) {
        try {
          SecUtils secUtils = SecUtils.getInstance();
          secUtils.createSelfSignedKeystore(guardDoc.getGuard().getGuardInfo().getID(), // cn
                                            guardDoc.getGuard().getKeystore(),
                                            guardDoc.getGuard().getKeystorePassword(),
                                            guardDoc.getGuard().getKeystorePassword(),
                                            guardDoc.getGuard().getGuardInfo().getID()); // alias for certificate
        }
        catch (GuanxiException ge) {
          logger.error("Can't create self signed keystore - secure Engine comms won't be available : ", ge);
          throw new ServletException(ge);
        }
      }

      // Create a truststore if one doesn't exist
      trustStoreFile = new File(guardDoc.getGuard().getTrustStore());
      if (!trustStoreFile.exists()) {
        try {
          SecUtils secUtils = SecUtils.getInstance();
          secUtils.createTrustStore(guardDoc.getGuard().getTrustStore(),
                                    guardDoc.getGuard().getTrustStorePassword());
        }
        catch (GuanxiException ge) {
          logger.error("Can't create truststore - secure Engine comms won't be available : ", ge);
          throw new ServletException(ge);
        }
      }
    }
    catch (Exception e) {
      logger.error("Guard init failure", e);
      throw new ServletException(e);
    }
  }

  public void destroy() {
    if (okToUnloadBCProvider) {
      /* Although addProvider() returns the ID of the newly installed provider,
       * we can't rely on this. If another webapp removes a provider from the list of
       * installed providers, all the other providers shuffle up the list by one, thus
       * invalidating the ID we got from addProvider().
       */
      try {
        for ( Provider currentProvider : Security.getProviders() ) {
          if (currentProvider.getName().equalsIgnoreCase(Guanxi.BOUNCY_CASTLE_PROVIDER_NAME)) {
            Security.removeProvider(Guanxi.BOUNCY_CASTLE_PROVIDER_NAME);
          }
        }
      }
      catch (SecurityException se) {
        /* We'll end up here if a security manager is installed and it refuses us
         * permission to remove the BouncyCastle provider
         */
      }
    }
  }

  /**
   * This filter is responsible for redirecting unauthenticated users to the WAYF service.
   */
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException, ServletException {
    HttpServletRequest httpRequest;
    HttpServletResponse httpResponse;
    org.guanxi.xal.sp.GuardDocument.Guard config;
    String sessionID, wayfLocation;
    
    httpRequest = (HttpServletRequest)request;
    httpResponse = (HttpServletResponse)response;

    // Get the configuration
    config = (org.guanxi.xal.sp.GuardDocument.Guard)filterConfig.getServletContext().getAttribute(Guanxi.CONTEXT_ATTR_GUARD_CONFIG);
    
    // Don't block web service calls from a Guanxi SAML Engine
    if ((httpRequest.getRequestURI().endsWith("guard.sessionVerifier"))   || 
        (httpRequest.getRequestURI().endsWith("guard.guanxiGuardACS"))    || 
        (httpRequest.getRequestURI().endsWith("guard.guanxiGuardlogout")) || 
        (httpRequest.getRequestURI().endsWith("guard.guanxiGuardPodder"))) {
      filterChain.doFilter(request, response);
      return;
    }

    if ( checkCookies(httpRequest, httpResponse, filterChain, config) ) {
      return;
    }
    logger.debug("No pod of attributes found - redirecting to the WAYF");
    
    sessionID = setPod(httpRequest);
    
    try {
      probeForEngineCertificate(httpRequest, config);
    }
    catch ( Exception e ) {
      logger.error("Secure probe to Engine failed", e);
      
      request.setAttribute("ERROR_ID", "ID_WAYF_WS_NOT_RESPONDING");
      request.setAttribute("ERROR_MESSAGE", e.getMessage());
      request.getRequestDispatcher("/WEB-INF/guanxi_sp_guard/jsp/sp_error.jsp").forward(request,
                                                                                        response);
      return;
    }
    
    try {
      wayfLocation = getWAYFLocation(httpRequest, httpResponse, sessionID, config);
      
      // Send the user to the WAYF or IdP
      httpResponse.sendRedirect(wayfLocation);
    }
    catch ( GuanxiException e ) {
      // thrown when the WAYF service is responding but it responds with an error
      logger.error("Engine WAYF Web Service returned error : " + e.getMessage());
      request.setAttribute("ERROR_ID", "ID_WAYF_WS_ERROR");
      request.setAttribute("ERROR_MESSAGE", e.getMessage());
      request.getRequestDispatcher("/WEB-INF/guanxi_sp_guard/jsp/sp_error.jsp").forward(request,
                                                                                        response);
      return;
    }
    catch ( Exception e ) {
      // thrown when the connection to the WAYF service cannot be made
      logger.error("Engine WAYF Web Service not responding", e);
      request.setAttribute("ERROR_ID", "ID_WAYF_WS_NOT_RESPONDING");
      request.setAttribute("ERROR_MESSAGE", e.getMessage());
      request.getRequestDispatcher("/WEB-INF/guanxi_sp_guard/jsp/sp_error.jsp").forward(request,
                                                                                        response);
      return;
    }
  }
  
  /**
   * This checks the available cookies to see if any of them indicate that the user
   * has already logged on. If the cookie has been found then there should also be
   * a Pod which will contain details about the original request.
   * 
   * @param httpRequest
   * @param httpResponse
   * @param filterChain
   * @param config
   * @return                  This will return true if the user has logged on
   * @throws IOException
   * @throws ServletException
   */
  private boolean checkCookies(HttpServletRequest httpRequest, HttpServletResponse httpResponse, FilterChain filterChain, org.guanxi.xal.sp.GuardDocument.Guard config) throws IOException, ServletException {
    String cookieName;
    Cookie[] cookies;
    
    cookieName = config.getCookie().getPrefix() + FileName.encode(config.getGuardInfo().getID());
    logger.debug("Looking for Guard cookie with name : " + cookieName);
    
    cookies    = httpRequest.getCookies();
    if (cookies != null) {
      for (int i = 0; i < cookies.length; i++) {
        logger.debug("Found cookie : " + cookies[i].getName());
        if (cookies[i].getName().equals(cookieName)) {
          // See if there's a pod for the request
          Pod pod = (Pod)filterConfig.getServletContext().getAttribute(cookies[i].getValue());

          // If there isn't then we must get rid of the cookie
          if (pod == null) {
            logger.debug("Found a Guard cookie but no Pod of attributes : " + cookies[i].getName());
            cookies[i].setMaxAge(0);
            httpResponse.addCookie(cookies[i]);
          }
          else {
            logger.debug("Found a Guard cookie with a Pod of attributes : " + cookies[i].getName());

            // Add any new parameters to the original request
            pod.setRequestParameters(httpRequest.getParameterMap());

            filterChain.doFilter(new GuardRequest(httpRequest,
                                                  pod,
                                                  attributePrefix),
                                 httpResponse);
            return true;
          }
        }
      }
    }
    return false;
  }
  
  /**
   * This sets the Pod of attributes relating to the original request. It
   * also returns the SessionId used to track the request.
   * 
   * @return
   */
  private String setPod(HttpServletRequest httpRequest) {
    String sessionID;
    Pod pod;
    
    // This is the session ID that we'll use to track the request
    sessionID = "GUARD_" + Utils.getUniqueID().replaceAll(":", "--");

    // Create a new Pod to encapsulate information for this session
    pod = new Pod();

    // Store the servlet context for later deactivation of the pod
    pod.setContext(filterConfig.getServletContext());

    // Store the original scheme and hostname
    pod.setRequestScheme(httpRequest.getScheme());
    pod.setHostName(httpRequest.getHeader("Host").replaceAll("/", ""));

    /* Store the parameters in the Pod as these are not guaranteed to be around in the
     * original request after the SAML workflow has finished. The servlet container will
     * only guarantee them for this request. After that, it can reuse the request object.
     */
    pod.setRequestParameters(httpRequest.getParameterMap());

    // Store the original URL including any query parameters
    if (httpRequest.getQueryString() != null) {
      pod.setRequestURL(httpRequest.getRequestURI() + "?" + httpRequest.getQueryString());
    }
    else {
      pod.setRequestURL(httpRequest.getRequestURI());
    }

    // Store the Pod in a session
    pod.setSessionID(sessionID);
    filterConfig.getServletContext().setAttribute(sessionID, pod);
    
    return sessionID;
  }
  
  /**
   * This will check to see if the communication with the Engine is using HTTPS. If it is
   * then this will probe the connection and retrieve the certificate associated with it.
   * 
   * @param httpRequest
   * @param config
   * @throws GuanxiException
   * @throws KeyStoreException
   * @throws IOException 
   * @throws FileNotFoundException 
   * @throws NoSuchAlgorithmException 
   */
  private void probeForEngineCertificate(HttpServletRequest httpRequest, org.guanxi.xal.sp.GuardDocument.Guard config) throws GuanxiException, KeyStoreException, CertificateException, NoSuchAlgorithmException, FileNotFoundException, IOException {
    EntityConnection engineConnection;
    X509Certificate  engineX509;
    KeyStore         guardTrustStore;
    
    if (filterConfig.getServletContext().getAttribute(config.getGuardInfo().getID() + "SECURE_CHECK_DONE") == null) {
      if (Util.isEngineSecure(config.getEngineInfo().getWAYFLocationService())) {
        logger.info("Probing for Engine certificate");

        /* If the Engine is using HTTPS then we'll need to connect to it, extract it's
         * certificate and add it to our truststore. To do that, we'll need to use our
         * own keystore to let the Guard authenticate us.
         */
        engineConnection = new EntityConnection(config.getEngineInfo().getWAYFLocationService(),
                                                                 config.getGuardInfo().getID(),
                                                                 config.getKeystore(),
                                                                 config.getKeystorePassword(),
                                                                 config.getTrustStore(),
                                                                 config.getTrustStorePassword(),
                                                                 EntityConnection.PROBING_ON);
        engineX509 = engineConnection.getServerCertificate();

        // We've got the Engine's X509 so add it to our truststore...
        guardTrustStore = KeyStore.getInstance("jks");
        guardTrustStore.load(new FileInputStream(config.getTrustStore()), config.getTrustStorePassword().toCharArray());
        // ...under it's Subject DN as an alias...
        guardTrustStore.setCertificateEntry(engineX509.getSubjectDN().getName(), engineX509);
        // ...and rewrite the trust store
        guardTrustStore.store(new FileOutputStream(config.getTrustStore()), config.getTrustStorePassword().toCharArray());

        // Mark the Engine as having been checked for secure comms
        filterConfig.getServletContext().setAttribute(config.getGuardInfo().getID() + "SECURE_CHECK_DONE", "SECURE");

        logger.info("Added : " + engineX509.getSubjectDN().getName() + " to truststore");
      }
      else {
        // Mark Guard as having been checked for secure comms
        filterConfig.getServletContext().setAttribute(config.getGuardInfo().getID() + "SECURE_CHECK_DONE", "NOT_SECURE");
      }
    }
  }
  
  /**
   * This will get the WAYF Location from the WAYF Location Service, returning the full valid URL for
   * redirection. This can throw a checked exception, which indicates that the WAYF service returned an
   * error but was reachable, or this can throw an unchecked exception which indicates that the WAYF
   * service was unreachable.
   * 
   * @param httpRequest
   * @param httpResponse
   * @param sessionID
   * @param config
   * @return
   * @throws GuanxiException
   */
  private String getWAYFLocation(HttpServletRequest httpRequest, HttpServletResponse httpResponse, String sessionID, org.guanxi.xal.sp.GuardDocument.Guard config) throws GuanxiException {
    String wayfLocation, queryString;
    EntityConnection wayfService;
    
    wayfLocation = null;
    queryString = config.getEngineInfo().getWAYFLocationService() + "?" + Guanxi.WAYF_PARAM_GUARD_ID + "=" + config.getGuardInfo().getID();
    queryString += "&" + Guanxi.WAYF_PARAM_SESSION_ID + "=" + sessionID;
    
    wayfService = new EntityConnection(queryString,
                                       config.getGuardInfo().getID(),
                                       config.getKeystore(),
                                       config.getKeystorePassword(),
                                       config.getTrustStore(),
                                       config.getTrustStorePassword(),
                                       EntityConnection.PROBING_OFF);
    wayfService.setDoOutput(true);
    wayfService.connect();
    wayfLocation = wayfService.getContentAsString();
    if (wayfLocation.equals(Guanxi.SESSION_VERIFIER_RETURN_VERIFIED)) {
    }

    if (Errors.isError(wayfLocation)) {
      throw new GuanxiException(wayfLocation);
    }

    logger.debug("Got WAYF location " + wayfLocation);

    // The target parameter is meant to come back as is from the IdP
    wayfLocation += "?shire=" + config.getEngineInfo().getAuthConsumerURL();
    wayfLocation += "&target=" + sessionID;
    wayfLocation += "&time=" + (System.currentTimeMillis() / 1000);
    wayfLocation += "&providerId=" + config.getGuardInfo().getID();
    
    // added in order to support WAYF->DS functionality
    // this forwards any query parameters to the WAYF
    if ( httpRequest.getQueryString() != null ) {
      wayfLocation += "&" + httpRequest.getQueryString();
    }
    
    return wayfLocation;
  }

  /**
   * Deactivates a Pod. This will cause a pod to disappear
   * from the servlet context and thus start a new Shibboleth
   * protocol session.
   *
   * @param pod Pod that needs deactivating
   */
  public static void deactivatePod(Pod pod) {
    if (pod != null) {
      pod.getContext().setAttribute(pod.getSessionID(), null);
    }
  }

  /**
   * Fills out any configuration options that can be determined programatically
   *
   * @param config FilterConfig
   * @param configDoc Guard configuration
   * @throws ServletException if an error occurs saving the updated configuration file
   */
  private void initConfigFile(FilterConfig config, GuardDocument configDoc) throws ServletException {
    boolean updated;
    String guardAppRoot;
    XmlOptions xmlOptions;
    
    updated = false;
    guardAppRoot = config.getServletContext().getRealPath("WEB-INF").replace(File.separator + "WEB-INF", "");

    if ( configDoc.getGuard().getTrustStore().startsWith("__GUARD_APP_ROOT__") ) {
      configDoc.getGuard().setTrustStore(configDoc.getGuard().getTrustStore().replace("__GUARD_APP_ROOT__", guardAppRoot));
      updated = true;
    }

    if (configDoc.getGuard().getKeystore().startsWith("__GUARD_APP_ROOT__")) {
      configDoc.getGuard().setKeystore(configDoc.getGuard().getKeystore().replace("__GUARD_APP_ROOT__", guardAppRoot));
      updated = true;
    }

    if (updated) {
      xmlOptions = new XmlOptions();
      xmlOptions.setSavePrettyPrint();
      xmlOptions.setSavePrettyPrintIndent(2);
      xmlOptions.setUseDefaultNamespace();

      try {
        configDoc.save(new File(config.getServletContext().getRealPath(config.getInitParameter(CONFIG_FILE_PARAM))), xmlOptions);
      }
      catch (IOException ioe) {
        throw new ServletException(ioe);
      }
    }
  }
  
  /**
   * This returns the prefix that is added to all the attribute names before they
   * are set as headers. By providing this method the jsp pages that process the
   * headers do not need to rely upon hard coded values that can go out of date.
   * 
   * @return
   */
  public static String getAttributePrefix() {
    return attributePrefix;
  }
}
