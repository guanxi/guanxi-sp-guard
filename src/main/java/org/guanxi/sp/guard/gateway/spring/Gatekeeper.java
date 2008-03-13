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

package org.guanxi.sp.guard.gateway.spring;

import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.context.ServletContextAware;
import org.guanxi.common.Pod;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.ServletContext;
import java.util.Enumeration;

/**
 * Spring application connector that works in conjunction with a Guanxi Guard. This represents the
 * application side of Shibboleth. A Guanxi Guard will be setup to block access to a web application
 * at the root level, which means it will add a Pod of attributes to all requests. This class then
 * acts as the filter for internal application functionality, applying access rules based on attributes
 * and their values supplied by the Guard.
 *
 * In effect, the Guard acts as the authenticator for the application, while this class acts as the
 * rule engine that decides which parts of the application will be accessible to bearers of attributes
 * with certain values. 
 *
 * @author Alistair Young alistairskye@googlemail.com
 */
public class Gatekeeper extends HandlerInterceptorAdapter implements ServletContextAware {
  /** If set to true, attribute rules are not processed and the application is open to all */
  private boolean debug = false;
  /** The name of the page that is displayed if no trusted attribute values can be found */
  private String accessDeniedPage = null;
  /** The name of the attribute to use to govern access to the application */
  private String letMeInAttribute = null;
  /** The values of letMeInAttribute to trust */
  private String[] letMeInAttributeValues = null;
  /** The ServletContext, passed to us by Spring as we are ServletContextAware */
  private ServletContext servletContext = null;

  /**
   * Initialise the interceptor
   */
  public void init() {
  }

  /**
   * Blocks access to a page based on the value of an attribute. The attribute to use is injected via the
   * letMeInAttribute property and the values which the interceptor accepts for that attribute are injected
   * via the letMeInAttributeValues property:
   *
   * <pre>
   *  <property name="letMeInAttribute"><value>urn:mace:dir:attribute-def:mail</value></property>
   *  <property name="letMeInAttributeValues">
   *    <list>
   *      <value>alistairskye@googlemail.com</value>
   *    </list>
   *  </property>
   * </pre>
   *
   * @param request Standard HttpServletRequest
   * @param response Standard HttpServletResponse
   * @param object handler
   * @return true if a trusted attribute and value are found, otherwise redirects to the page defined by the
   * injected property accessDeniedPage.
   * @throws Exception if an error occurs
   */
  public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object object) throws Exception {
    // If the debug property is set, just let the request through.
    if (debug) return true;

    // Don't block redirects to the access denied page.
    if (request.getRequestURI().contains(accessDeniedPage)) return true;

    // Start looking for a Guanx Guard cookie
    Cookie[] cookies = request.getCookies();
    if (cookies != null) {
      for (int c=0; c<cookies.length; c++) {
        // ...and look for a Guanxi Guard one.
        if (cookies[c].getName().startsWith("GUANXI_GUARD_SERVICE_PROVIDER_")) {
          
          /* If we have a Guanxi Guard cookie, it means authentication has taken
           * place and the SAML attributes are in a Pod in the request.
           * The cookie contains the session ID set up by the Guard, into which
           * the Podder has dumped the Pod of attributes.
           */
          Pod pod = (Pod)servletContext.getAttribute(cookies[c].getValue());
          
          if (pod != null) {
            Enumeration e = pod.getBag().getAttributeNames();
            String attributeName = null;
            
            while (e.hasMoreElements()) {
              attributeName = (String)e.nextElement();

              // Find a match for the access attribute
              if (attributeName.equals(letMeInAttribute)) {
                for (String letMeInAttributeValue : letMeInAttributeValues) {
                  if (pod.getBag().getAttributeValue(attributeName).equalsIgnoreCase(letMeInAttributeValue)) {
                    return true;
                  }
                } // for (String letMeInAttributeValue : letMeInAttributeValues)
              } // if (attributeName.equals(letMeInAttribute))
            } // while (e.hasMoreElements())
          } // if (pod != null)
        } // if (cookies[c].getName().startsWith("GUANXI_GUARD_SERVICE_PROVIDER_"))
      } // for (int c=0; c<cookies.length; c++)
    } // if (cookies != null)

    // If we get here it means either the access attribute is missing or it has an untrusted value
    request.getRequestDispatcher(accessDeniedPage).forward(request, response);
    return false;
  }

  public void postHandle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Object object, ModelAndView modelAndView) throws Exception {
  }

  public void afterCompletion(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Object object, Exception exception) throws Exception {
  }

  // Called by Spring as we are ServletContextAware
  public void setServletContext(ServletContext servletContext) { this.servletContext = servletContext; }

  // Setters
  public void setDebug(boolean debug) { this.debug = debug; }
  public void setAccessDeniedPage(String accessDeniedPage) { this.accessDeniedPage = accessDeniedPage; }
  public void setLetMeInAttribute(String letMeInAttribute) { this.letMeInAttribute = letMeInAttribute; }
  public void setLetMeInAttributeValues(String[] letMeInAttributeValues) { this.letMeInAttributeValues = letMeInAttributeValues; }

  // Getters
  public boolean getDebug() { return debug; }
  public String getAccessDeniedPage() { return accessDeniedPage; }
  public String getLetMeInAttribute() { return letMeInAttribute; }
  public String[] getLetMeInAttributeValues() { return letMeInAttributeValues; }
}
