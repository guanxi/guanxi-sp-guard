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

import javax.servlet.*;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 * <font size=5><b></b></font>
 *
 * @author Alistair Young alistair@smo.uhi.ac.uk
 */
public class Guard extends GuardBase {
  public void init(FilterConfig config) throws ServletException {
    initBase(config);
    loadSecurityProvider();
    initKeystore();
    initTruststore();
  }

  public void destroy() {
    unloadSecurityProvider();
  }

  public void doFilter(ServletRequest request, ServletResponse response,
                       FilterChain filterChain) throws IOException, ServletException {
    HttpServletRequest httpRequest = (HttpServletRequest)request;
    HttpServletResponse httpResponse = (HttpServletResponse)response;

    // Don't block web service calls from a Guanxi SAML Engine
    if (passthru(httpRequest)) {
      filterChain.doFilter(request, response);
      return;
    }

    logger.debug("Looking for Guard cookie with name : " + cookieName);

    // If no profiles are specified then something's wrong
    Profile profile = null;
    if ((guardConfig.getProfiles() == null) ||
        (guardConfig.getProfiles().getProfileArray() == null) ||
        (guardConfig.getProfiles().getProfileArray().length == 0)) {
      logger.info("Guard has no profiles. Free resources.");
      request.setAttribute("ERROR_ID", "ID_WAYF_WS_ERROR");
      request.setAttribute("ERROR_MESSAGE", "There are no profiles defined.");
      request.getRequestDispatcher("/WEB-INF/guanxi_sp_guard/jsp/sp_error.jsp").forward(request, response);
      return;
    }

    // Work out what profile to use for the resource
    profile = getProfile(httpRequest);

    // Are we handling a profile URL we don't support?
    if (profile == null) {
      request.setAttribute("ERROR_ID", "ID_WAYF_WS_ERROR");
      request.setAttribute("ERROR_MESSAGE", "Unsupported profile");
      request.getRequestDispatcher("/WEB-INF/guanxi_sp_guard/jsp/sp_error.jsp").forward(request, response);
      return;
    }

    if (profile.name.equals("none")) {
      logger.info("Free access to resource : " + profile.resourceURI);
      filterChain.doFilter(request, response);
      return;
    }

    // From now it's authenticated profile based access
    Pod podFromCookie = doCookies(httpRequest, httpResponse);
    if (podFromCookie != null) {
      filterChain.doFilter(new GuardRequest(httpRequest,
                                            podFromCookie,
                                            guardConfig.getGuardInfo().getAttributePrefix()),
                           response);
      return;
    }

    initEngineComms(request, response);

    logger.debug("No pod of attributes found - starting profile search");

    Pod pod = createPod(request);
    pod.setRequestURL((profile.resourceURI));

    if (profile.name.equals("shibboleth")) {
      logger.info("Shibboleth : " + profile.resourceURI);
      gotoWAYF(pod.getSessionID(), request, response);
      return;
    }

    if (profile.name.equals("saml2-web-browser-sso")) {
      if ((profile.entityID == null) || (profile.entityID.length() == 0)) {
        // We need an idp parameter for this profile
        logger.error("SAML2 Web Browser SSO : " + profile.resourceURI + " : missing entityid");
        request.setAttribute("ERROR_ID", "ID_NEED_ALL_PARAMETERS");
        request.setAttribute("ERROR_MESSAGE", "missing entityid parameter");
        request.getRequestDispatcher("/WEB-INF/guanxi_sp_guard/jsp/sp_error.jsp").forward(request, response);
        return;
      }

      logger.info("SAML2 Web Browser SSO : " + profile.resourceURI + " : " + profile.entityID);
      gotoWBSSO(pod.getSessionID(), profile.entityID, request, response);
      return;
    }
  }
}
