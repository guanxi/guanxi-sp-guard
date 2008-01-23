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

   Revision 1.7  2007/01/17 17:39:42  alistairskye
   Now gets cookie prefix from config

   Revision 1.6  2006/12/14 14:09:27  alistairskye
   Updated to use Guanxi.CONTEXT_ATTR_GUARD_CONFIG

   Revision 1.5  2006/12/14 12:41:48  alistairskye
   Updated to make use of config object instead of individual params in context.
   Now handles all cookie processing.

   Revision 1.4  2006/11/23 14:32:28  alistairskye
   Updated to redirect using scheme and hostname as it was redirecting to HTTPS if the Guard was using HTTPS

   Revision 1.3  2006/01/16 14:31:01  alistairskye
   Modified process() to not set MaxAge if the cookie is transient

   Revision 1.2  2005/08/23 15:38:10  alistairskye
   Cookie name now contains Guard ID to fix reauthentication problem

   Revision 1.1  2005/08/15 14:00:37  alistairskye
   Links a Pod to a session cookie

   Revision 1.5  2005/08/15 13:42:21  alistairskye
   Removed decide()

   Revision 1.4  2005/08/15 13:39:06  alistairskye
   No longer implements PolicyEngine

   Revision 1.3  2005/08/11 15:27:14  alistairskye
   Now gets the cookie info the the servlet context

   Revision 1.2  2005/08/10 14:54:36  alistairskye
   Updated license

   Revision 1.1.1.1  2005/08/10 14:19:23  alistairskye
   Guanxi Service Provider

*/

package org.guanxi.sp.guard;

import org.guanxi.common.Pod;
import org.guanxi.common.definitions.Guanxi;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.ServletException;
import java.io.IOException;

/**
 * <font size=5><b></b></font>
 *
 * @author Alistair Young alistair@smo.uhi.ac.uk
 */
public class Podder extends HttpServlet {
  /** The config object placed in the servlet context by the Guard filter */
  private org.guanxi.xal.sp.GuardDocument.Guard config = null;
  /** The age of the cookie to set */
  private int cookieAge;

  public void init() throws ServletException {
    // Get the config
    config = (org.guanxi.xal.sp.GuardDocument.Guard)getServletContext().getAttribute(Guanxi.CONTEXT_ATTR_GUARD_CONFIG);

    if (config == null)
      throw new ServletException("Podder can't get config");

    // Sort out the cookie's age
    String cookieMaxAge = config.getCookie().getAge().getStringValue();
    String cookieAgeUnits = config.getCookie().getAge().getUnits().toString();
    if (cookieAgeUnits.equals("seconds")) cookieAge = Integer.parseInt(cookieMaxAge);
    else if (cookieAgeUnits.equals("minutes")) cookieAge = Integer.parseInt(cookieMaxAge) * 60;
    else if (cookieAgeUnits.equals("hours")) cookieAge = Integer.parseInt(cookieMaxAge) * 3600;
    else if (cookieAgeUnits.equals("days")) cookieAge = Integer.parseInt(cookieMaxAge) * 86400;
    else if (cookieAgeUnits.equals("weeks")) cookieAge = Integer.parseInt(cookieMaxAge) * 604800;
    else if (cookieAgeUnits.equals("months")) cookieAge = Integer.parseInt(cookieMaxAge) * 2419200;
    else if (cookieAgeUnits.equals("years")) cookieAge = Integer.parseInt(cookieMaxAge) * 29030400;
    else if (cookieAgeUnits.equals("transient")) cookieAge = -1;
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
    String cookieDomain = (config.getCookie().getDomain() == null) ? "" : config.getCookie().getDomain();

    // "id" is the sessionID set by the Guard filter
    Pod pod = (Pod)getServletContext().getAttribute(request.getParameter("id"));

    // Create a new Guard cookie
    Cookie cookie = new Cookie(config.getCookie().getPrefix() + config.getGuardInfo().getID(), pod.getSessionID());
    cookie.setDomain(cookieDomain);
    cookie.setPath(config.getCookie().getPath());

    // If cookieAge is -1, don't set the MaxAge so we get a transient, in-memory cookie
    if (cookieAge != -1)
      cookie.setMaxAge(cookieAge);

    // Add a cookie that points to the pod for this request
    response.addCookie(cookie);

    // Redirect to the requested resource. The filter will handle access and attributes
    response.sendRedirect(pod.getRequestScheme() + "://" + pod.getHostName() + pod.getRequestURL());
  }
}
