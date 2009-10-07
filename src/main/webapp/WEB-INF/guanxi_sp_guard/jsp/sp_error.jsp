<%@ page import="java.util.Locale"%>
<%@ page import="java.util.ResourceBundle"%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%
  ResourceBundle common = ResourceBundle.getBundle("messages.common", new Locale(request.getHeader("Accept-Language")));
  ResourceBundle msg = ResourceBundle.getBundle("messages.sp", new Locale(request.getHeader("Accept-Language")));
%>
<html>
  <head><title><%= msg.getString("error.page.title")%></title>
    <style type="text/css">
      <!--
      body {
        background-color: #FFFFFF;
        margin-left: 20px;
        margin-top: 20px;
        margin-right: 20px;
        margin-bottom: 20px;
        font-family:Verdana, Arial, Helvetica, sans-serif;
        background-image: url(<%= request.getContextPath() %>/guanxi_sp/images/watermark.gif );
      }
      -->
    </style>
  </head>
  <body>
  <div style="border:1px solid black; width:50%; height:20%; background-image:url(<%= request.getContextPath() %>/guanxi_sp/images/formback.gif); background-repeat:repeat-x repeat-y; margin: 0 auto;">
    <div style="padding:20px; margin: 0 auto;">
      <%= msg.getString("error.page.text")%>
      <br><br>
      <%= request.getAttribute("ERROR_MESSAGE") %>
    </div>
   </div>

   <div style="width:50%; margin: 0 auto;">
     <div align="left"><strong>Guanxi@<%= common.getString("institution.display.name")%></strong></div>
   </div>
  </body>
</html>