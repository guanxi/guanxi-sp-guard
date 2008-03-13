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
import org.guanxi.common.definitions.Guanxi;
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
 * @author Alistair Young alistair@smo.uhi.ac.uk
 */
public class Logout extends HttpServlet {
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
    org.guanxi.xal.sp.GuardDocument.Guard config = (org.guanxi.xal.sp.GuardDocument.Guard)getServletContext().getAttribute(Guanxi.CONTEXT_ATTR_GUARD_CONFIG);

    boolean loggedOut = false;
    Cookie[] cookies = request.getCookies();
    if (cookies != null) {
      for (int c = 0; c < cookies.length; c++) {
        if (cookies[c].getName().equals(config.getCookie().getPrefix() + config.getGuardInfo().getID())) {
          Pod pod = (Pod)getServletContext().getAttribute(cookies[c].getValue());
          if (pod != null) {
            Guard.deactivatePod(pod);
            loggedOut = true;
            request.setAttribute("LOGOUT_MESSAGE", "You have successfully logged out of the SP");
          }
        }
      }
    }

    if (!loggedOut)
      request.setAttribute("LOGOUT_MESSAGE", "You have not successfully logged out of the SP");

    request.getRequestDispatcher("/WEB-INF/guanxi_sp_guard/jsp/logout.jsp").forward(request, response);
  }
}
