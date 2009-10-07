<%@ page import="java.util.Enumeration,
                 java.io.PrintWriter"%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
  <head><title>Guanxi Shibboleth parameters</title></head>
  <body>
  <%
    String name, value;
    PrintWriter p = response.getWriter();
    Enumeration e = request.getHeaderNames();
    while (e.hasMoreElements()) {
      name = (String)e.nextElement();
      value = request.getHeader(name);
      p.print(name + " --> " + value + "<br>");
    }
    p.print("<br /><br /><a href=\"http://localhost:8080/protectedapp/guard.guanxiGuardlogout\">Logout of the SP</a>");
    p.print("<br /><br /><a href=\"http://localhost:8080/guanxi_idp/shibb/logout\">Logout of the IdP</a>");
    p.flush();
    p.close();
  %>
  </body>
</html>