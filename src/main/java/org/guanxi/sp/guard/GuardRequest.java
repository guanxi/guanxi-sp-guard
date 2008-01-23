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

   Revision 1.14  2007/01/04 13:44:31  alistairskye
   Updated to use new Pod bag methods.
   Updated javadoc.

   Revision 1.13  2006/08/30 12:22:54  alistairskye
   Updated to add support for request attributes to fix problems with spring based applications

   Revision 1.12  2006/06/02 08:54:06  alistairskye
   Updated getHeader() to look for the header name as is before trying all lowercase as the SAML attributes can be mixed case.

   Revision 1.11  2006/05/22 15:26:31  alistairskye
   Fixed bug where header names were case sensitive. The servlet spec says they should be case insensitive

   Revision 1.10  2006/05/18 13:46:51  alistairskye
   Fixed bug in getParameter() for when param value is null

   Revision 1.9  2006/05/18 13:32:58  alistairskye
   Now stores a reference to the Pod
   Now implements the methods:
   getParameter
   getParameterMap
   getParameterNames
   getParameterValues

   Revision 1.8  2006/05/18 09:25:48  alistairskye
   Now gets the request from the Pod

   Revision 1.7  2006/04/05 13:27:41  alistairskye
   Updated to prefix attributes with configurable prefix string

   Revision 1.6  2005/08/25 15:52:27  alistairskye
   Added cookies

   Revision 1.5  2005/08/16 13:53:09  alistairskye
   Prefixes attributes with HTTP_ instead of GUANXI_

   Revision 1.4  2005/08/16 12:17:21  alistairskye
   Added check for no assertions

   Revision 1.3  2005/08/12 12:46:15  alistairskye
   Added license

   Revision 1.2  2005/08/12 09:03:32  alistairskye
   Added SAML attributes

   Revision 1.1  2005/08/11 14:16:49  alistairskye
   Guanxi specific HttpServletRequest wrapper to handle SAML attributes as request headers

*/

package org.guanxi.sp.guard;

import org.guanxi.common.Pod;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.Cookie;
import java.util.*;

/**
 * The GuardRequest represents the Guard in the browser. It encapsulates all the original Request
 * information and adds attributes as request headers, obtained from an IdP via en Engine.
 *
 * @author Alistair Young alistair@smo.uhi.ac.uk
 */
public class GuardRequest extends HttpServletRequestWrapper {
  Pod requestPod = null;
  Hashtable headers = null;
  Cookie[] cookies = null;

  public GuardRequest(HttpServletRequest request, Pod pod, String attributePrefix) {
    super(request);

    requestPod = pod;

    headers = new Hashtable();

    cookies = new Cookie[super.getCookies().length];
    cookies = super.getCookies();

    String buffer = null;
    Enumeration requestHeaderNames = super.getHeaderNames();
    while (requestHeaderNames.hasMoreElements()) {
      buffer = (String)requestHeaderNames.nextElement();
      // Servlet spec states that header names are case insensitive
      headers.put(buffer.toLowerCase(), super.getHeader(buffer));
    }

    // Make sure there are attributes to process
    if (pod.getBag().hasAttributes()) {
      Enumeration samlAttributeNames = pod.getBag().getAttributeNames();
      while (samlAttributeNames.hasMoreElements()) {
        buffer = (String)samlAttributeNames.nextElement();
        headers.put(attributePrefix + buffer, pod.getBag().getAttributeValue(buffer));
      }
    }
  }

  public String getParameter(String name) {
    /* The original parameter values are stored as String[] no matter how
     * many of them there are. i.e. a param with one value will still
     * return a String[] for that value.
     */
    String[] values = (String[])requestPod.getRequestParameters().get(name);

    // Return the first value of the param
    return (values != null) ? values[0] : null;
  }

  public Map getParameterMap() {
    return requestPod.getRequestParameters();
  }

  public Enumeration getParameterNames() {
    return new Enumeration() {
      Iterator names = requestPod.getRequestParameters().keySet().iterator();

      public boolean hasMoreElements() {
        return names.hasNext();
      }

      public Object nextElement() {
        return names.next();
      }
    };
  }

  public Enumeration getAttributeNames() {
    return super.getAttributeNames();
  }

  public Object getAttribute(String name) {
    return super.getAttribute(name);
  }

  public void setAttribute(String name, Object value) {
    super.setAttribute(name, value);
  }

  public String[] getParameterValues(String name) {
    // See note on getParameter
    return (String[])requestPod.getRequestParameters().get(name);
  }

  public String getHeader(String name) {
    // Look for the header name as is. If it's not there, try all lower case
    return (headers.get(name) != null) ? (String)headers.get(name) : (String)headers.get(name.toLowerCase());
  }

  public Enumeration getHeaderNames() {
    return headers.keys();
  }

  public Enumeration getHeaders(String name) {
    return super.getHeaders(name);
  }

  public Cookie[] getCookies() {
    return cookies;
  }
}
