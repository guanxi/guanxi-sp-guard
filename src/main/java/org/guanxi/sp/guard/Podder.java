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
import org.apache.log4j.Logger;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.ServletException;
import java.io.IOException;
import java.util.ResourceBundle;

/**
 * Adds a Pod full of attributes to the system
 *
 * @author alistair
 * @author chris
 */
@SuppressWarnings("serial")
public class Podder extends HttpServlet {
  private static final Logger logger = Logger.getLogger(Podder.class.getName());

  /** The config object placed in the servlet context by the Guard filter */
  private ResourceBundle config = null;
  /** The age of the cookie to set */
  private int cookieAge;

  public void init() throws ServletException {

    // Get the config
    config = (ResourceBundle)getServletContext().getAttribute(Definitions.CONTEXT_ATTR_GUARD_CONFIG);

    if (config == null)
      throw new ServletException("Podder can't get config");

    // Sort out the cookie's age
    String cookieMaxAge = config.getString("cookie.age");
    String cookieAgeUnits = config.getString("cookie.age.units");
    if (cookieAgeUnits.equals("seconds"))
      cookieAge = Integer.parseInt(cookieMaxAge);
    else if (cookieAgeUnits.equals("minutes"))
      cookieAge = Integer.parseInt(cookieMaxAge) * 60;
    else if (cookieAgeUnits.equals("hours"))
      cookieAge = Integer.parseInt(cookieMaxAge) * 3600;
    else if (cookieAgeUnits.equals("days"))
      cookieAge = Integer.parseInt(cookieMaxAge) * 86400;
    else if (cookieAgeUnits.equals("weeks"))
      cookieAge = Integer.parseInt(cookieMaxAge) * 604800;
    else if (cookieAgeUnits.equals("months"))
      cookieAge = Integer.parseInt(cookieMaxAge) * 2419200;
    else if (cookieAgeUnits.equals("years"))
      cookieAge = Integer.parseInt(cookieMaxAge) * 29030400;
    else if (cookieAgeUnits.equals("transient"))
      cookieAge = -1;
  }

  public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    process(request, response);
  }

  public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    process(request, response);
  }

  /**
   * This is the Guard's Podder module. This is the last stop in the Guanxi SP chain. By the time
   * we arrive here, the process has gone through the steps:
   *
   * Guard has blocked request and forwarded to WAYF/SSO
   * Engine has received all the attributes
   * Engine has forwarded the attributes to the Guard's AttributeConsumer module
   * Guard's AttributeConsumer module has added the attributes to the Pod
   *
   * So now we create a Guanxi Guard cookie and associate it with the completed Pod. The cookie
   * will let the request through the Guard now.
   *
   * @param request Standard HttpServletRequest
   * @param response Standard HttpServletResponse
   * @throws ServletException if an error occurs
   * @throws IOException if an error occurs
   */
  public void process(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    // Sort out the cookie path
    String cookieDomain = (config.getString("cookie.domain") == null) ? "" : postProcessGetGuardId(config.getString("cookie.domain"), request);

    String cookieName = config.getString("cookie.prefix") + FileName.encode(postProcessGetGuardId(config.getString("entityid"), request));

    // "id" is the sessionID set by the Guard filter
    Pod pod = (Pod)getServletContext().getAttribute(request.getParameter("id"));

    // Create a new Guard cookie
    logger.debug("Creating a new Guard cookie : " + cookieName);
    Cookie cookie = new Cookie(cookieName,
                               pod.getSessionID());
    cookie.setDomain(cookieDomain);
    cookie.setPath(config.getString("cookie.path"));

    // If cookieAge is -1, don't set the MaxAge so we get a transient, in-memory cookie
    if (cookieAge != -1)
      cookie.setMaxAge(cookieAge);

    // Add a cookie that points to the pod for this request
    response.addCookie(cookie);

    // Redirect to the requested resource. The filter will handle access and attributes
    response.sendRedirect(pod.getRequestScheme() + "://" + pod.getHostName() + pod.getRequestURL());
  }

  /**
   * Opportunity for extending filters to dynamically control the guard id
   *
   * @param id The current Guard ID
   * @param httpRequest Servlet request
   * @return The new Guard ID. Could be the same as the current one
   */
  protected String postProcessGetGuardId(String id, HttpServletRequest httpRequest) {
	  return id;
  }
}
