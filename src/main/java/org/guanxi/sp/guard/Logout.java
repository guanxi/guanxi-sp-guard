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

import org.apache.log4j.Logger;
import org.guanxi.common.Pod;
import org.guanxi.common.filters.FileName;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import java.io.IOException;

/**
 * <p>Logout</p>
 *
 * This servlet provides an HTTP binding for logout functionality.
 * It calls the low level Guard API to do the actual logout.
 *
 * @author alistair
 * @author chris
 */
@SuppressWarnings("serial")
public class Logout extends HttpServlet {

	private Logger logger = Logger.getLogger(Logout.class.getName());

  public void init() throws ServletException {
  }

  public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    processLogout(request, response);
  }

  public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    processLogout(request, response);
  }

  /**
   * Does the logging out. The method looks for the user's Guard cookie in the request
   * and if it finds it, it extracts the corresponding Pod and sends it
   * to Guard.deactivatePod() for processing.
   *
   * @param request Standard HttpServletRequest
   * @param response Standard HttpServletRequest
   * @throws ServletException if an error occurrs
   * @throws IOException if an error occurrs
   */
  public void processLogout(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    GuardConfig config = (GuardConfig)getServletContext().getAttribute(Definitions.CONTEXT_ATTR_GUARD_CONFIG);
    String cookieName = config.get("cookie.prefix") + FileName.encode(postProcessGetGuardId(config.get("entityid"), request));

    boolean loggedOut = false;
    Cookie[] cookies = request.getCookies();

    logger.debug("processLogout: attempting to find cookie: " + cookieName);

    if (cookies != null) {
      for (int c = 0; c < cookies.length; c++) {
        if (cookies[c].getName().equals(cookieName)) {

        	logger.debug("processLogout: found cookie: " + cookieName);
          Pod pod = (Pod)getServletContext().getAttribute(cookies[c].getValue());
          if (pod != null) {
        	  logger.debug("processLogout: deactivating pod for session: " + pod.getSessionID());
            Guard.deactivatePod(pod);
            loggedOut = true;
            request.setAttribute(getLogoutMessageAttributeName(), getLogoutSuccessMessage());
          }
        }
      }
    }

    if (!loggedOut)
      request.setAttribute(getLogoutMessageAttributeName(), getLogoutErrorMessage());

    // See if we have to redirect anywhere after logging out
    if ((request.getParameter("goto") != null) && (request.getParameter("goto").length() > 0)) {
      response.sendRedirect(request.getParameter("goto"));
    }
    else {
      request.getRequestDispatcher(getLogoutResource()).forward(request, response);
    }
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

  protected String getLogoutMessageAttributeName() {
	  return "LOGOUT_MESSAGE";
  }

  protected String getLogoutSuccessMessage() {
	  return "You have successfully logged out of the SP";
  }

  protected String getLogoutErrorMessage() {
	  return "You have not successfully logged out of the SP";
  }

  protected String getLogoutResource() {
	  return "/WEB-INF/guanxi_sp_guard/jsp/logout.jsp";
  }
}
