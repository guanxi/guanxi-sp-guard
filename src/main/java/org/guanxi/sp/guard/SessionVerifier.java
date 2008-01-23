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

   Revision 1.1  2006/11/22 14:33:39  alistairskye
   REST service to replace Axis RPC call for verifying a Guard session

*/

package org.guanxi.sp.guard;

import org.guanxi.common.definitions.Guanxi;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletException;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * REST service for verifying a previously sent session id. An Engine should send it's information as:
 *
 * http://localhost/protectedapp/guanxi.sessionVerifier?sessionid=XXX
 *
 * @author Alistair Young
 */
public class SessionVerifier extends HttpServlet {
  public void init() throws ServletException {
  }

  public void destroy() {
  }

  public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    process(request, response);
  }

  public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    process(request, response);
  }

  /**
   * Verifies a session that the Guard previously sent to the Engine's WAYFLocation service.
   *
   * @param request Standard HttpServletRequest with the param:
   * sessionid
   * @param response Standard HttpServletResponse with a value of one of:
   * Guanxi.SESSION_VERIFIER_RETURN_VERIFIED
   * Guanxi.SESSION_VERIFIER_RETURN_NOT_VERIFIED
   * @throws ServletException if an error occurs
   * @throws IOException if an error occurs
   */
  public void process(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    String sessionID = request.getParameter(Guanxi.SESSION_VERIFIER_PARAM_SESSION_ID);
    PrintWriter out = response.getWriter();
    
    // Have we got a pod for this session?
    if (getServletContext().getAttribute(sessionID) != null) {
      out.write(Guanxi.SESSION_VERIFIER_RETURN_VERIFIED);
    }
    else {
      out.write(Guanxi.SESSION_VERIFIER_RETURN_NOT_VERIFIED);
    }

    out.close();
  }
}
