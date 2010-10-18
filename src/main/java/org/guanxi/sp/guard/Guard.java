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

import org.guanxi.common.Pod;
import org.guanxi.common.filters.FileName;

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
  }

  public void destroy() {}

  public void doFilter(ServletRequest request, ServletResponse response,
                       FilterChain filterChain) throws IOException, ServletException {
    HttpServletRequest httpRequest = (HttpServletRequest)request;
    HttpServletResponse httpResponse = (HttpServletResponse)response;

    // Dynamically determine the cookie name in case it needs to be changed at runtime
    cookieName = guardConfig.get("cookie.prefix") + FileName.encode(postProcessGetGuardId(guardConfig.get("entityid"), httpRequest));

    // Don't block web service calls from a Guanxi SAML Engine
    if (passthru(httpRequest)) {
      filterChain.doFilter(request, response);
      return;
    }

    logger.debug("Looking for Guard cookie with name : " + cookieName);

    // From now it's authenticated profile based access
    Pod podFromCookie = doCookies(httpRequest, httpResponse);
    if (podFromCookie != null) {
      GuardRequest guardRequest = new GuardRequest(httpRequest, podFromCookie,
                                                   guardConfig.get("attribute.prefix"));
      guardRequest.setGuardCookieName(cookieName);

      preSuccessFilterChain(guardRequest);
      filterChain.doFilter(guardRequest, response);
      
      return;
    }

    logger.debug("No pod of attributes found - starting profile search");

    Pod pod = createPod(request);
    pod.setRequestURL(((HttpServletRequest) request).getRequestURI());
    gotoEngineGPS(pod.getSessionID(), request, response);
    
    return;
  }
}
