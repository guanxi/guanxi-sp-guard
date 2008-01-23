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
//: The Initial Developer of the Original Code is Alistair Young alistair@smo.uhi.ac.uk.
//: Portions created by SMO WWW Development Group are Copyright (C) 2005 SMO WWW Development Group.
//: All Rights Reserved.
//:
/* CVS Header
   $Id$
   $Log$
   Revision 1.1.1.1  2008/01/23 15:28:59  alistairskye
   Standalone Guard module

   Revision 1.40  2007/03/30 08:59:21  alistairskye
   Now calls initConfigFile() before putting completed config in servlet context

   Revision 1.39  2007/03/30 08:48:33  alistairskye
   Updated to automatically fill in truststore and keystore paths in the config file

   Revision 1.38  2007/02/09 11:33:37  alistairskye
   Added guard.guanxiGuardlogout to list of pass through URLs

   Revision 1.37  2007/02/09 11:32:46  alistairskye
   Added guard.guanxiGuardPodder to list of pass through URLs

   Revision 1.36  2007/01/17 17:43:00  alistairskye
   Now puts it's identity info (ID, cookie prefix, cookie name) into the servlet context for use by webapps it protects.
   Now gets the cookie prefix from the config.
   Stores servlet context in Pod.
   Added static method deactivatePod()

   Revision 1.35  2007/01/04 13:46:22  alistairskye
   Removed verify() method. All session verification requests from an Engine are now handled by the SessionVerifier service.

   Revision 1.34  2006/12/14 14:08:43  alistairskye
   Updated to use Guanxi.CONTEXT_ATTR_GUARD_CONFIG

   Revision 1.33  2006/12/14 12:40:50  alistairskye
   Updated to make use of config object instead of individual params in context.
   Moved all cookie processing to org.guanxi.sp.guard.Podder

   Revision 1.32  2006/11/27 10:41:38  alistairskye
   Updated init() to create a default keystore and truststore if they don't exist

   Revision 1.31  2006/11/27 09:36:36  alistairskye
   Added ERROR_MESSAGE to error conditions for sp_error.jsp to display

   Revision 1.30  2006/11/23 14:33:21  alistairskye
   Updated to add request scheme and hostname to pod

   Revision 1.29  2006/11/23 10:53:53  alistairskye
   Added certificate probing

   Revision 1.28  2006/11/22 14:58:14  alistairskye
   Converted to use the Engine's REST WAYFLocation service instead of Axis RPC

   Revision 1.27  2006/08/30 12:18:05  alistairskye
   Updated to transfer new parameters to GuardRequest to fix problems with spring based applications

   Revision 1.26  2006/07/25 14:53:09  alistairskye
   Refactored to use XMLBeans for configuration and to place the Guard XMLBeans object in the servlet context to share with other parts of the Guard

   Revision 1.25  2006/05/19 07:00:23  alistairskye
   Fixed bug where transient cookies couldn't be set

   Revision 1.24  2006/05/18 13:33:28  alistairskye
   Now stores original request parameters in the Pod

   Revision 1.23  2006/05/18 09:26:37  alistairskye
   Updated to use new GuardRequest

   Revision 1.22  2006/04/05 13:33:52  alistairskye
   Updated to prefix attributes with configurable prefix string.
   Fixed bug where it was adding null query string if one didn't exist
   Now sends it's session ID in target parameter

   Revision 1.21  2006/03/04 21:49:25  alistairskye
   Updated to add the query string to the protected URL

   Revision 1.20  2006/01/30 10:03:14  alistairskye
   Updated doFilter to allow web service calls to the Guard through the filter

   Revision 1.19  2006/01/26 08:56:50  alistairskye
   Updated to use Logging.DEFAULT_SP_GUARD_CONFIG_FILE

   Revision 1.18  2006/01/21 18:36:10  alistairskye
   Modified to use Logging.DEFAULT_SP_LOG_DIR

   Revision 1.17  2005/12/09 12:34:32  alistairskye
   Modified to allow empty domain cookies

   Revision 1.16  2005/10/25 13:46:27  alistairskye
   Localised the error messages

   Revision 1.15  2005/10/25 12:36:40  alistairskye
   Now forwards to error page in new JSP structure

   Revision 1.14  2005/10/25 11:32:06  alistairskye
   Fixed request forwarding on error

   Revision 1.13  2005/09/22 08:33:00  alistairskye
   Changed initLogger to use Logging.DEFAULT_IDP_CONFIG_FILE

   Revision 1.12  2005/08/25 11:02:21  alistairskye
   Fixed IllegalState bug where the filter was allowing the request object to leak into the application being guarded, causing redirection errors

   Revision 1.11  2005/08/23 15:38:25  alistairskye
   Cookie name now contains Guard ID to fix reauthentication problem

   Revision 1.10  2005/08/23 13:22:59  alistairskye
   Updated location of sp_error.jsp

   Revision 1.9  2005/08/19 12:24:33  alistairskye
   Updated to process AuthConsumerURL from the config file

   Revision 1.8  2005/08/16 14:58:35  alistairskye
   Added web service error checking

   Revision 1.7  2005/08/16 12:14:06  alistairskye
   Fixed some bugs getting config info

   Revision 1.6  2005/08/15 16:23:30  alistairskye
   Added logging

   Revision 1.5  2005/08/15 13:57:07  alistairskye
   Some minor refactoring

   Revision 1.4  2005/08/11 15:26:45  alistairskye
   Added cookie config processing

   Revision 1.3  2005/08/11 14:14:59  alistairskye
   Added cookie processing and request wrapping

   Revision 1.2  2005/08/10 14:54:36  alistairskye
   Updated license

   Revision 1.1.1.1  2005/08/10 14:19:23  alistairskye
   Guanxi Service Provider

*/

package org.guanxi.sp.guard;

import org.guanxi.common.definitions.Guanxi;
import org.guanxi.common.definitions.Logging;
import org.guanxi.common.*;
import org.guanxi.common.security.SecUtils;
import org.guanxi.xal.sp.GuardDocument;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import org.apache.log4j.RollingFileAppender;
import org.apache.log4j.xml.DOMConfigurator;
import org.apache.xmlbeans.XmlOptions;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.servlet.*;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.Cookie;
import java.io.File;
import java.io.IOException;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Security;
import java.security.Provider;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

/**
 * <font size=5><b></b></font>
 *
 * @author Alistair Young alistair@smo.uhi.ac.uk
 */
public class Guard implements Filter {
  /** Our logger */
  private static Logger log = Logger.getLogger(Guard.class);
  /** The name of the web.xml init-param that holds the location of the config file */
  private static final String CONFIG_FILE_PARAM = "configFile";
  /** This Filter's config object as set by the container */
  private FilterConfig filterConfig = null;
  /** Indicates if we can unload the BouncyCastle security provider */
  private boolean okToUnloadBCProvider = false;

  public void init(FilterConfig config) throws ServletException {
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

      // Get the logger ready
      initLogger(config.getServletContext());

      // Load up the config file...
      GuardDocument guardDoc = GuardDocument.Factory.parse(new File((String)filterConfig.getServletContext().getRealPath(config.getInitParameter(CONFIG_FILE_PARAM))));

      // Sort out any config options that can be done automatically
      initConfigFile(config, guardDoc);
      
      // Make the config available to the rest of the Guard as an XMLBeans Guard object
      filterConfig.getServletContext().setAttribute(Guanxi.CONTEXT_ATTR_GUARD_CONFIG, guardDoc.getGuard());

      /* Register our ID and cookie details in the servlet context
       * to allow applications to know who their Guard is.
       */
      filterConfig.getServletContext().setAttribute(Guanxi.CONTEXT_ATTR_GUARD_ID,
                                                    guardDoc.getGuard().getGuardInfo().getID());
      filterConfig.getServletContext().setAttribute(Guanxi.CONTEXT_ATTR_GUARD_COOKIE_PREFIX,
                                                    guardDoc.getGuard().getCookie().getPrefix());
      filterConfig.getServletContext().setAttribute(Guanxi.CONTEXT_ATTR_GUARD_COOKIE_NAME,
                                                    guardDoc.getGuard().getCookie().getPrefix() +
                                                    guardDoc.getGuard().getGuardInfo().getID());

      /* If we don't have a keystore, create a self signed one now. The keystore will hold
       * our private key and public key certificate in case we need to communicate with an
       * Engine's services via HTTPS.
       */
      File keyStoreFile = new File(guardDoc.getGuard().getKeystore());
      if (!keyStoreFile.exists()) {
        try {
          SecUtils secUtils = SecUtils.getInstance();
          secUtils.createSelfSignedKeystore(guardDoc.getGuard().getGuardInfo().getID(), // cn
                                            guardDoc.getGuard().getKeystore(),
                                            guardDoc.getGuard().getKeystorePassword(),
                                            guardDoc.getGuard().getKeystorePassword(),
                                            guardDoc.getGuard().getGuardInfo().getID()); // alias for certificate
        }
        catch(GuanxiException ge) {
          log.error("Can't create self signed keystore - secure Engine comms won't be available : ", ge);
          throw new ServletException(ge);
        }
      }

      // Create a truststore if one doesn't exist
      File trustStoreFile = new File(guardDoc.getGuard().getTrustStore());
      if (!trustStoreFile.exists()) {
        try {
          SecUtils secUtils = SecUtils.getInstance();
          secUtils.createTrustStore(guardDoc.getGuard().getTrustStore(),
                                    guardDoc.getGuard().getTrustStorePassword());
        }
        catch(GuanxiException ge) {
          log.error("Can't create truststore - secure Engine comms won't be available : ", ge);
          throw new ServletException(ge);
        }
      }
    }
    catch(Exception e) {
      log.error("Guard init failure", e);
      throw new ServletException(e);
    }
  }

  public void destroy() {
    if (okToUnloadBCProvider) {
      Provider[] providers = Security.getProviders();

      /* Although addProvider() returns the ID of the newly installed provider,
       * we can't rely on this. If another webapp removes a provider from the list of
       * installed providers, all the other providers shuffle up the list by one, thus
       * invalidating the ID we got from addProvider().
       */
      try {
        for (int i=0; i < providers.length; i++) {
          if (providers[i].getName().equalsIgnoreCase(Guanxi.BOUNCY_CASTLE_PROVIDER_NAME)) {
            Security.removeProvider(Guanxi.BOUNCY_CASTLE_PROVIDER_NAME);
          }
        }
      }
      catch(SecurityException se) {
        /* We'll end up here if a security manager is installed and it refuses us
         * permission to remove the BouncyCastle provider
         */
      }
    }
  }

  public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException, ServletException {
    HttpServletRequest httpRequest = (HttpServletRequest)request;
    HttpServletResponse httpResponse = (HttpServletResponse)response;

    // Get the config
    org.guanxi.xal.sp.GuardDocument.Guard config = (org.guanxi.xal.sp.GuardDocument.Guard)filterConfig.getServletContext().getAttribute(Guanxi.CONTEXT_ATTR_GUARD_CONFIG);

    // Don't block web service calls from a Guanxi SAML Engine
    if ((httpRequest.getRequestURI().endsWith("guard.sessionVerifier")) ||
        (httpRequest.getRequestURI().endsWith("guard.guanxiGuardACS")) ||
        (httpRequest.getRequestURI().endsWith("guard.guanxiGuardlogout")) ||
        (httpRequest.getRequestURI().endsWith("guard.guanxiGuardPodder"))) {
      filterChain.doFilter(request, response);
      return;
    }

    Cookie[] cookies = httpRequest.getCookies();
    if (cookies != null) {
      for (int i=0; i<cookies.length; i++) {
        if (cookies[i].getName().equals(config.getCookie().getPrefix() + config.getGuardInfo().getID())) {
          // See if there's a pod for the request
          Pod pod = (Pod)filterConfig.getServletContext().getAttribute(cookies[i].getValue());

          // If there isn't then we must get rid of the cookie
          if (pod == null) {
            cookies[i].setMaxAge(0);
            httpResponse.addCookie(cookies[i]);
          }
          else {
            // Add any new parameters to the original request
            pod.setRequestParameters(request.getParameterMap());

            filterChain.doFilter(new GuardRequest(httpRequest, pod, config.getGuardInfo().getAttributePrefix()), response);
            return;
          }
        }
      }
    }

    // This is the session ID that we'll use to track the request
    String sessionID = "GUARD_" + Utils.getUniqueID();

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
    if (httpRequest.getQueryString() != null)
      pod.setRequestURL(httpRequest.getRequestURI() + "?" + httpRequest.getQueryString());
    else
     pod.setRequestURL(httpRequest.getRequestURI());

    // Store the Pod in a session
    pod.setSessionID(sessionID);
    filterConfig.getServletContext().setAttribute(sessionID, pod);

    if (filterConfig.getServletContext().getAttribute(config.getGuardInfo().getID() + "SECURE_CHECK_DONE") == null) {
      try {
        if (Util.isEngineSecure(config.getEngineInfo().getWAYFLocationService())) {
          log.info("Probing for Engine certificate");

          /* If the Engine is using HTTPS then we'll need to connect to it, extract it's
           * certificate and add it to our truststore. To do that, we'll need to use our
           * own keystore to let the Guard authenticate us.
           */
          EntityConnection engineConnection = new EntityConnection(config.getEngineInfo().getWAYFLocationService(),
                                                                   config.getGuardInfo().getID(),
                                                                   config.getKeystore(),
                                                                   config.getKeystorePassword(),
                                                                   config.getTrustStore(),
                                                                   config.getTrustStorePassword(),
                                                                   EntityConnection.PROBING_ON);
          X509Certificate engineX509 = engineConnection.getServerCertificate();

          // We've got the Engine's X509 so add it to our truststore...
          KeyStore guardTrustStore = KeyStore.getInstance("jks");
          guardTrustStore.load(new FileInputStream(config.getTrustStore()),
                               config.getTrustStorePassword().toCharArray());
          // ...under it's Subject DN as an alias...
          guardTrustStore.setCertificateEntry(engineX509.getSubjectDN().getName(), engineX509);
          // ...and rewrite the trust store
          guardTrustStore.store(new FileOutputStream(config.getTrustStore()),
                                config.getTrustStorePassword().toCharArray());

          // Mark the Engine as having been checked for secure comms
          filterConfig.getServletContext().setAttribute(config.getGuardInfo().getID() + "SECURE_CHECK_DONE", "SECURE");

          log.info("Added : " + engineX509.getSubjectDN().getName() + " to truststore");
        }
        else {
          // Mark Guard as having been checked for secure comms
          filterConfig.getServletContext().setAttribute(config.getGuardInfo().getID() + "SECURE_CHECK_DONE", "NOT_SECURE");
        }
      }
      catch(Exception e) {
        log.error("Secure probe to Engine failed", e);
        request.setAttribute("ERROR_ID", "ID_WAYF_WS_NOT_RESPONDING");
        request.setAttribute("ERROR_MESSAGE", e.getMessage());
        request.getRequestDispatcher("/WEB-INF/guanxi_sp_guard/jsp/sp_error.jsp").forward(request, response);
        return;
      }
    }

    /* Call the Engine's web service to set up a session and get the location of the WAYF.
     * If there isn't a WAYF, this will just be the location of the IdP.
     */
    String wayfLocation = null;
    try {
      String queryString = config.getEngineInfo().getWAYFLocationService() + "?" +
                           Guanxi.WAYF_PARAM_GUARD_ID + "=" + config.getGuardInfo().getID();
      queryString += "&" + Guanxi.WAYF_PARAM_SESSION_ID + "=" + sessionID;
      EntityConnection wayfService = new EntityConnection(queryString,
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
    }
    catch(Exception e) {
      log.error("Engine WAYF Web Service not responding", e);
      request.setAttribute("ERROR_ID", "ID_WAYF_WS_NOT_RESPONDING");
      request.setAttribute("ERROR_MESSAGE", e.getMessage());
      request.getRequestDispatcher("/WEB-INF/guanxi_sp_guard/jsp/sp_error.jsp").forward(request, response);
      return;
    }

    if (Errors.isError(wayfLocation)) {
      log.error("Engine WAYF Web Service returned error : " + wayfLocation);
      request.setAttribute("ERROR_ID", "ID_WAYF_WS_ERROR");
      request.setAttribute("ERROR_MESSAGE", wayfLocation);
      request.getRequestDispatcher("/WEB-INF/guanxi_sp_guard/jsp/sp_error.jsp").forward(request, response);
      return;
    }

    log.debug("Got WAYF location " + wayfLocation);

    // The target parameter is meant to come back as is from the IdP
    wayfLocation += "?shire=" + config.getEngineInfo().getAuthConsumerURL();
    wayfLocation += "&target=" + sessionID;
    wayfLocation += "&time=" + "sdfsdsdf";
    wayfLocation += "&providerId=" + config.getGuardInfo().getID();

    // Send the user to the WAYF or IdP
    httpResponse.sendRedirect(wayfLocation);
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

  private void initLogger(ServletContext context) throws GuanxiException {
    DOMConfigurator.configure(context.getRealPath(Logging.DEFAULT_SP_GUARD_CONFIG_FILE));

    PatternLayout defaultLayout = new PatternLayout(Logging.DEFAULT_LAYOUT);

    RollingFileAppender rollingFileAppender = new RollingFileAppender();
    rollingFileAppender.setName("GuanxiGuard");
    try {
      rollingFileAppender.setFile(context.getRealPath(Logging.DEFAULT_SP_GUARD_LOG_DIR + "guanxi-sp-guard.log"), true, false, 0);
    }
    catch(IOException ioe) {
      throw new GuanxiException(ioe);
    }
    rollingFileAppender.setMaxFileSize("1MB");
    rollingFileAppender.setMaxBackupIndex(5);
    rollingFileAppender.setLayout(defaultLayout);

    log.removeAllAppenders();
    log.addAppender(rollingFileAppender);
    log.setAdditivity(false);
  }

  /**
   * Fills out any config options that can be determined programatically
   *
   * @param config FilterConfig
   * @param configDoc Guard config
   * @throws ServletException if an error occurs saving the updated config file
   */
  private void initConfigFile(FilterConfig config, GuardDocument configDoc) throws ServletException {
    boolean updated = false;
    String guardAppRoot = config.getServletContext().getRealPath("WEB-INF").replaceAll(Utils.SLASH + "WEB-INF", "");
    
    if (configDoc.getGuard().getTrustStore().startsWith("__GUARD_APP_ROOT__")) {
      configDoc.getGuard().setTrustStore(configDoc.getGuard().getTrustStore().replaceAll("__GUARD_APP_ROOT__", guardAppRoot));
      updated = true;
    }

    if (configDoc.getGuard().getKeystore().startsWith("__GUARD_APP_ROOT__")) {
      configDoc.getGuard().setKeystore(configDoc.getGuard().getKeystore().replaceAll("__GUARD_APP_ROOT__", guardAppRoot));
      updated = true;
    }

    if (updated) {
      XmlOptions xmlOptions = new XmlOptions();
      xmlOptions.setSavePrettyPrint();
      xmlOptions.setSavePrettyPrintIndent(2);
      xmlOptions.setUseDefaultNamespace();

      try {
        configDoc.save(new File(config.getServletContext().getRealPath(config.getInitParameter(CONFIG_FILE_PARAM))), xmlOptions);
      }
      catch(IOException ioe) {
        throw new ServletException(ioe);
      }
    }
  }
}
