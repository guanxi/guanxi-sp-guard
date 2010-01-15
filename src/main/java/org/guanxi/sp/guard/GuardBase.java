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

import org.guanxi.common.*;
import org.guanxi.common.security.SecUtils;
import org.guanxi.common.filters.FileName;
import org.guanxi.common.definitions.Guanxi;
import org.guanxi.xal.sp.GuardDocument;
import org.guanxi.xal.sp.GuardProfile;
import org.apache.log4j.Logger;
import org.apache.xmlbeans.XmlOptions;
import org.apache.xmlbeans.XmlException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.*;
import java.security.Security;
import java.security.KeyStore;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.io.File;
import java.io.IOException;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.URLEncoder;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

public abstract class GuardBase implements Filter {
  /** Our logger */
  protected Logger logger = null;
  /** The name of the web.xml init-param that holds the location of the config file */
  protected static final String CONFIG_FILE_PARAM = "configFile";
  /** This Filter's config object as set by the container */
  protected FilterConfig filterConfig = null;
  /** Indicates if we can unload the BouncyCastle security provider */
  protected boolean okToUnloadBCProvider = false;
  protected org.guanxi.xal.sp.GuardDocument.Guard guardConfig = null;
  protected String cookieName = null;

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

  public abstract void doFilter(ServletRequest request, ServletResponse response,
                                FilterChain filterChain) throws IOException, ServletException;

  protected void initBase(FilterConfig config) {
    logger = Logger.getLogger(this.getClass().getName());

    // Store the config for later
    filterConfig = config;

    // Load up the config file...
    GuardDocument guardDoc = null;
    try {
      guardDoc = GuardDocument.Factory.parse(new File((String)filterConfig.getServletContext().getRealPath(config.getInitParameter(CONFIG_FILE_PARAM))));
    }
    catch(IOException ioe) {
      logger.error("Can't load Guard config : ", ioe);
    }
    catch(XmlException xe) {
      logger.error("Can't parse Guard config : ", xe);
    }

    // Sort out any config options that can be done automatically
    try {
      initConfigFile(config, guardDoc);
    }
    catch(ServletException se) {
      logger.error("Can't init Guard config : ", se);
    }

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

    guardConfig = (org.guanxi.xal.sp.GuardDocument.Guard)filterConfig.getServletContext().getAttribute(Guanxi.CONTEXT_ATTR_GUARD_CONFIG);
    cookieName = guardConfig.getCookie().getPrefix() + FileName.encode(guardConfig.getGuardInfo().getID());
  }

  protected void loadSecurityProvider() {
    /* If we try to add the BouncyCastle provider but another Guanxi::Guard running
     * in another webapp in the same container has already done so, then we'll get
     * -1 returned from the method, in which case, we should leave unloading of the
     * provider to the particular Guanxi::Guard that loaded it.
     */
    if ((Security.addProvider(new BouncyCastleProvider())) != -1) {
      // We've loaded it, so we should unload it
      okToUnloadBCProvider = true;
    }
  }

  protected void unloadSecurityProvider() {
    if (okToUnloadBCProvider) {
      Provider[] providers = Security.getProviders();

      /* Although addProvider() returns the ID of the newly installed provider,
       * we can't rely on this. If another webapp removes a provider from the list of
       * installed providers, all the other providers shuffle up the list by one, thus
       * invalidating the ID we got from addProvider().
       */
      try {
        for (int i = 0; i < providers.length; i++) {
          if (providers[i].getName().equalsIgnoreCase(Guanxi.BOUNCY_CASTLE_PROVIDER_NAME)) {
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

  protected void initKeystore() {
    /* If we don't have a keystore, create a self signed one now. The keystore will hold
     * our private key and public key certificate in case we need to communicate with an
     * Engine's services via HTTPS.
     */
    File keyStoreFile = new File(guardConfig.getKeystore());
    if (!keyStoreFile.exists()) {
      try {
        SecUtils secUtils = SecUtils.getInstance();
        secUtils.createSelfSignedKeystore(guardConfig.getGuardInfo().getID(), // cn
                                          guardConfig.getKeystore(),
                                          guardConfig.getKeystorePassword(),
                                          guardConfig.getKeystorePassword(),
                                          guardConfig.getGuardInfo().getID()); // alias for certificate
      }
      catch (GuanxiException ge) {
        logger.error("Can't create self signed keystore - secure Engine comms won't be available : ", ge);
      }
    }
  }

  protected void initTruststore() {
    // Create a truststore if one doesn't exist
    File trustStoreFile = new File(guardConfig.getTrustStore());
    if (!trustStoreFile.exists()) {
      try {
        SecUtils secUtils = SecUtils.getInstance();
        secUtils.createTrustStore(guardConfig.getTrustStore(),
                                  guardConfig.getTrustStorePassword());
      }
      catch (GuanxiException ge) {
        logger.error("Can't create truststore - secure Engine comms won't be available : ", ge);
      }
    }
  }

  /**
   * Fills out any config options that can be determined programatically
   *
   * @param config FilterConfig
   * @param configDoc Guard config
   * @throws javax.servlet.ServletException if an error occurs saving the updated config file
   */
  protected void initConfigFile(FilterConfig config, GuardDocument configDoc) throws ServletException {
    boolean updated = false;
    String guardAppRoot = config.getServletContext().getRealPath("WEB-INF").replace(File.separator + "WEB-INF",
                                                                                    "");

    if (configDoc.getGuard().getTrustStore().startsWith("__GUARD_APP_ROOT__")) {
      configDoc.getGuard().setTrustStore(configDoc.getGuard().getTrustStore().replace("__GUARD_APP_ROOT__",
                                                                                      guardAppRoot));
      updated = true;
    }

    if (configDoc.getGuard().getKeystore().startsWith("__GUARD_APP_ROOT__")) {
      configDoc.getGuard().setKeystore(configDoc.getGuard().getKeystore().replace("__GUARD_APP_ROOT__",
                                                                                  guardAppRoot));
      updated = true;
    }

    if (updated) {
      XmlOptions xmlOptions = new XmlOptions();
      xmlOptions.setSavePrettyPrint();
      xmlOptions.setSavePrettyPrintIndent(2);
      xmlOptions.setUseDefaultNamespace();

      try {
        configDoc.save(new File(config.getServletContext().getRealPath(config.getInitParameter(CONFIG_FILE_PARAM))),
                       xmlOptions);
      }
      catch (IOException ioe) {
        throw new ServletException(ioe);
      }
    }
  }

  protected Pod doCookies(HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
    Cookie[] cookies = httpRequest.getCookies();
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
            return pod;
          }
        }
      }
    }

    return null;
  }

  protected Pod createPod(ServletRequest request) {
    HttpServletRequest httpRequest = (HttpServletRequest)request;

    // Create a new Pod to encapsulate information for this session
    Pod pod = new Pod();

    // Store the servlet context for later deactivation of the pod
    pod.setContext(filterConfig.getServletContext());

    // Store the original scheme and hostname
    pod.setRequestScheme(request.getScheme());
    pod.setHostName(httpRequest.getHeader("Host").replaceAll("/", ""));

    /* Store the parameters in the Pod as these are not guaranteed to be around in the
     * original request after the SAML workflow has finished. The servlet container will
     * only guarantee them for this request. After that, it can reuse the request object.
     */
    pod.setRequestParameters(request.getParameterMap());

    // Store the original URL including any query parameters
    if (((HttpServletRequest)request).getQueryString() != null)
      pod.setRequestURL(httpRequest.getRequestURI() + "?" + httpRequest.getQueryString());
    else
      pod.setRequestURL(httpRequest.getRequestURI());

    // Store the Pod in a session
    String sessionID = "GUARD_" + Utils.getUniqueID().replaceAll(":", "--");
    pod.setSessionID(sessionID);
    filterConfig.getServletContext().setAttribute(sessionID, pod);

    return pod;
  }

  protected void initEngineComms(ServletRequest request, ServletResponse response) throws ServletException, IOException {
    if (filterConfig.getServletContext().getAttribute(guardConfig.getGuardInfo().getID() + "SECURE_CHECK_DONE") == null) {
      try {
        if (Util.isEngineSecure(guardConfig.getEngineInfo().getWAYFLocationService())) {
          logger.info("Probing for Engine certificate");

          /* If the Engine is using HTTPS then we'll need to connect to it, extract it's
           * certificate and add it to our truststore. To do that, we'll need to use our
           * own keystore to let the Guard authenticate us.
           */
          EntityConnection engineConnection = new EntityConnection(guardConfig.getEngineInfo().getWAYFLocationService(),
                                                                   guardConfig.getGuardInfo().getID(),
                                                                   guardConfig.getKeystore(),
                                                                   guardConfig.getKeystorePassword(),
                                                                   guardConfig.getTrustStore(),
                                                                   guardConfig.getTrustStorePassword(),
                                                                   EntityConnection.PROBING_ON);
          X509Certificate engineX509 = engineConnection.getServerCertificate();

          // We've got the Engine's X509 so add it to our truststore...
          KeyStore guardTrustStore = KeyStore.getInstance("jks");
          guardTrustStore.load(new FileInputStream(guardConfig.getTrustStore()),
                               guardConfig.getTrustStorePassword().toCharArray());
          // ...under it's Subject DN as an alias...
          guardTrustStore.setCertificateEntry(engineX509.getSubjectDN().getName(),
                                              engineX509);
          // ...and rewrite the trust store
          guardTrustStore.store(new FileOutputStream(guardConfig.getTrustStore()),
                                guardConfig.getTrustStorePassword().toCharArray());

          // Mark the Engine as having been checked for secure comms
          filterConfig.getServletContext().setAttribute(guardConfig.getGuardInfo().getID() + "SECURE_CHECK_DONE",
                                                        "SECURE");

          logger.info("Added : " + engineX509.getSubjectDN().getName() + " to truststore");
        }
        else {
          // Mark Guard as having been checked for secure comms
          filterConfig.getServletContext().setAttribute(guardConfig.getGuardInfo().getID() + "SECURE_CHECK_DONE",
                                                        "NOT_SECURE");
        }
      }
      catch (Exception e) {
        logger.error("Secure probe to Engine failed", e);
        request.setAttribute("ERROR_ID", "ID_WAYF_WS_NOT_RESPONDING");
        request.setAttribute("ERROR_MESSAGE", e.getMessage());
        request.getRequestDispatcher("/WEB-INF/guanxi_sp_guard/jsp/sp_error.jsp").forward(request,
                                                                                          response);
        return;
      }
    }
  }

  protected void gotoWAYF(String sessionID, ServletRequest request, ServletResponse response) {
    /* Call the Engine's web service to set up a session and get the location of the WAYF.
     * If there isn't a WAYF, this will just be the location of the IdP.
     */
    String wayfLocation = null;
    try {
      String queryString = guardConfig.getEngineInfo().getWAYFLocationService() + "?" + Guanxi.WAYF_PARAM_GUARD_ID + "=" + guardConfig.getGuardInfo().getID();
      queryString += "&" + Guanxi.WAYF_PARAM_SESSION_ID + "=" + sessionID;
      EntityConnection wayfService = new EntityConnection(queryString,
                                                          guardConfig.getGuardInfo().getID(),
                                                          guardConfig.getKeystore(),
                                                          guardConfig.getKeystorePassword(),
                                                          guardConfig.getTrustStore(),
                                                          guardConfig.getTrustStorePassword(),
                                                          EntityConnection.PROBING_OFF);
      wayfService.setDoOutput(true);
      wayfService.connect();
      wayfLocation = wayfService.getContentAsString();

      if (Errors.isError(wayfLocation)) {
        logger.error("Engine WAYF Web Service returned error : " + wayfLocation);
        request.setAttribute("ERROR_ID", "ID_WAYF_WS_ERROR");
        request.setAttribute("ERROR_MESSAGE", wayfLocation);
        try {
          request.getRequestDispatcher("/WEB-INF/guanxi_sp_guard/jsp/sp_error.jsp").forward(request, response);
        }
        catch (Exception ex) {}
      }

      logger.debug("Got WAYF location " + wayfLocation);

      /* The target parameter is for the private use of the SP and
       * is meant to come back as is from the IdP
       */
      wayfLocation += "?shire=" + URLEncoder.encode(guardConfig.getEngineInfo().getAuthConsumerURL(), "UTF-8");
      wayfLocation += "&target=" + URLEncoder.encode(sessionID, "UTF-8");
      wayfLocation += "&time=" + (System.currentTimeMillis() / 1000);
      wayfLocation += "&providerId=" + URLEncoder.encode(guardConfig.getGuardInfo().getID(), "UTF-8");

      // Send the user to the WAYF or IdP
      ((HttpServletResponse)response).sendRedirect(wayfLocation);
    }
    catch (Exception e) {
      logger.error("Engine WAYF Web Service not responding", e);
      request.setAttribute("ERROR_ID", "ID_WAYF_WS_NOT_RESPONDING");
      request.setAttribute("ERROR_MESSAGE", e.getMessage());
      try {
        request.getRequestDispatcher("/WEB-INF/guanxi_sp_guard/jsp/sp_error.jsp").forward(request, response);
      }
      catch (Exception ex) {}
    }
  }

  protected boolean passthru(HttpServletRequest httpRequest) {
    // Don't block web service calls from a Guanxi SAML Engine
    if ((httpRequest.getRequestURI().endsWith("guard.sessionVerifier")) ||
        (httpRequest.getRequestURI().endsWith("guard.guanxiGuardACS")) ||
        (httpRequest.getRequestURI().endsWith("guard.guanxiGuardlogout")) ||
        (httpRequest.getRequestURI().endsWith("guard.guanxiGuardPodder"))) {
      return true;
    }

    return false;
  }

  protected Profile getProfile(HttpServletRequest httpRequest) {
    Pattern pattern = null;
    Matcher matcher = null;

    GuardProfile[] guardProfiles = guardConfig.getProfiles().getProfileArray();
    for (GuardProfile guardProfile : guardProfiles) {
      pattern = Pattern.compile(guardProfile.getPath());
      matcher = pattern.matcher(httpRequest.getRequestURI());
      
      if (matcher.find()) {
        Profile profile = new Profile();
        profile.name = guardProfile.getName();

        if (guardProfile.getName().equals("none")) {
          profile.resourceURI = matcher.group(1) + matcher.group(2);
        }

        if (guardProfile.getName().equals("shibboleth")) {
          profile.resourceURI = matcher.group(1) + matcher.group(2);
        }

        if (guardProfile.getName().equals("saml2-web-browser-sso")) {
          // The entityID can come from the URL itself or a query param
          if (guardProfile.getBinding() != null) {
            if (guardProfile.getBinding().equalsIgnoreCase("rest")) {
              // app/s2wbsso/entityid/resource ...
              profile.entityID = matcher.group(3);
              profile.resourceURI = matcher.group(1) + matcher.group(4);
            }
          }
          else {
            // app/resource/?entityid= ...
            profile.entityID = httpRequest.getParameter("entityid");
            profile.resourceURI = matcher.group(1) + matcher.group(2);
          }
        }

        return profile;
      }
    }

    return null;
  }

  protected void gotoWBSSO(String sessionID, String entityID, ServletRequest request, ServletResponse response) {
    try {
      String wbssoLocation = guardConfig.getEngineInfo().getSAML2WBSSOService() + "?" + Guanxi.WAYF_PARAM_GUARD_ID + "=" + guardConfig.getGuardInfo().getID();
      wbssoLocation += "&" + Guanxi.WAYF_PARAM_SESSION_ID + "=" + sessionID;
      wbssoLocation += "&" + "entityID" + "=" + entityID;

      // Send the user to the WAYF or IdP
      ((HttpServletResponse)response).sendRedirect(wbssoLocation);
    }
    catch (IOException ioe) {
      logger.error("Engine WAYF Web Service not responding", ioe);
      request.setAttribute("ERROR_ID", "ID_WAYF_WS_NOT_RESPONDING");
      request.setAttribute("ERROR_MESSAGE", ioe.getMessage());
      try {
        request.getRequestDispatcher("/WEB-INF/guanxi_sp_guard/jsp/sp_error.jsp").forward(request, response);
      }
      catch (Exception ex) {}
    }
  }
}
