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
