<%@ page import="java.util.Enumeration,
                 java.io.PrintWriter"%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
  <!-- https://localhost:8443/protectedapp/saml2wbsso/headers.jsp?idp=GUANXI-2053069741 -->
  <head><title>Guanxi SAML2 Web Browser SSO parameters</title></head>
  <body>
  <%
    String name, value;
    PrintWriter p = response.getWriter();
    Enumeration e = request.getHeaderNames();
    while (e.hasMoreElements()) {
      name = (String)e.nextElement();
      value = request.getHeader(name);
      if (name.startsWith("HTTP_")) {
        p.print(name + " --> " + value + "<br>");
      }
    }
    p.print("<br /><br /><a href=\"https://localhost:8443/protectedapp/guard.guanxiGuardlogout\">Logout of the SP</a>");
    p.print("<br /><br /><a href=\"https://localhost:8443/guanxi_idp/shibb/logout\">Logout of the IdP</a>");
    p.flush();
    p.close();
  %>
  </body>
</html>