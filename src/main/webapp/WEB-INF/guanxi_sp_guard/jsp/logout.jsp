<%@ page import="java.util.Locale"%>
<%@ page import="java.util.ResourceBundle"%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%
  ResourceBundle msg = ResourceBundle.getBundle("messages.sp", request.getLocale());
%>
<html>
  <head><title><%= msg.getString("guard.logout.page.title")%></title>
    <style type="text/css">
      <!--
      body {
        background-color: #FFFFFF;
        margin-left: 20px;
        margin-top: 20px;
        margin-right: 20px;
        margin-bottom: 20px;
        font-family:Verdana, Arial, Helvetica, sans-serif;
        background-image: url(images/watermark.gif);
      }
      -->
    </style>
  </head>
  <body>
    <center><%= msg.getString("guard.logout.page.text")%></center>
  </body>
</html>