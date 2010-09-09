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

import org.guanxi.common.Bag;
import org.guanxi.common.GuanxiException;
import org.guanxi.common.Pod;
import org.apache.log4j.Logger;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletException;
import java.io.*;

/**
 * The AttributeConsumer service will load up the Pod previously created by the Podder service and add
 * the SAML Attributes in a Bag which it will place in the Pod. These are convenience objects for getting
 * hold of attributes without having to parse raw SAML.
 * If an application requires access to the full SAML Response it can parse the String representation of
 * the raw SAML that the AttributeConsumer services stores in the Bag.
 *
 * @author Alistair Young alistair@codebrane.com
 * @author Davide Zanatta davide.zanatta@gmail.com - bug fixing
 * @author Marcin Mielnicki mielniczu@o2.pl - bug fixing
 */
@SuppressWarnings("serial")
public class AttributeConsumer extends HttpServlet {
  private static final Logger logger = Logger.getLogger(AttributeConsumer.class.getName());

  public void init() throws ServletException {
  }

  public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    process(request, response);
  }

  public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    process(request, response);
  }

  public void process(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    Bag bag = null;

    try {
      bag = getBag(request);
    }
    catch(GuanxiException ge) {
      logger.error("Error receiving attributes from Engine: " + ge.getMessage());
    }
    
    // Load up the specified session's Pod...
    Pod pod = (Pod)getServletContext().getAttribute(bag.getSessionID());
    // ...and add the bag of attributes
    pod.setBag(bag);

    ServletOutputStream os = response.getOutputStream();
    os.write("OK".getBytes());
    os.close();
  }

  private Bag getBag(HttpServletRequest request) throws GuanxiException {
    String json = request.getParameter(Definitions.REQUEST_PARAMETER_SAML_ATTRIBUTES);
    if (json != null) {
      return new Bag(json);
    }
    else {
      throw new GuanxiException("No attributes");
    }
  }
}
