<%@ page import="java.util.ResourceBundle"%>
<%@ page import="java.util.Locale"%>
<%@ page import="java.io.File"%>
<%
  ResourceBundle msg = ResourceBundle.getBundle("messages.sp_index", new Locale(request.getHeader("Accept-Language")));
  ResourceBundle siteMsg = ResourceBundle.getBundle("messages.site", new Locale(request.getHeader("Accept-Language")));
%>
<html>
  <head>
    <title><%= msg.getString("ID_PAGE_TITLE")%></title>
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
  <%
      File configFile = new File(getServletConfig().getServletContext().getRealPath("/WEB-INF/config/guanxi-sp-engine.xml"));
      boolean isEngine = configFile.exists();
      configFile = new File(getServletConfig().getServletContext().getRealPath("/WEB-INF/guanxi_sp_guard/config/guanxi-sp-guard.xml"));
      boolean isGuard = configFile.exists();
    %>
    <div style="border:1px solid black; width:50%; height:20%; background-image:url(images/formback.gif); background-repeat:repeat-x repeat-y; margin: 0 auto;">
      <div style="padding:20px; margin: 0 auto;">
        <%= msg.getString("ID_SP_MESSAGE")%>
      </div>
     </div>

    <br><br>

    <div style="border:1px solid black; width:50%; height:20%; background-image:url(images/formback.gif); background-repeat:repeat-x repeat-y; margin: 0 auto;">
      <div style="padding:20px; margin: 0 auto;">
        <%= msg.getString("ID_SP_DOC_TEXT")%><br><br>
        <a href="http://www.guanxi.uhi.ac.uk/index.php/Service_Provider"><%= msg.getString("ID_SP_DOC_LINK")%></a><br><br>
      </div>
    </div>

    <!-- If we're a Guard, display the Guard info and setup link -->
    <% if (isGuard) { %>
    <div style="border:1px solid black; width:50%; height:20%; background-image:url(images/formback.gif); background-repeat:repeat-x repeat-y; margin: 0 auto;">
      <div style="padding:20px; margin: 0 auto;">
        <%= msg.getString("ID_GUARD_MESSAGE")%><br><br>
      </div>
     </div>
    <% } %>

    <br><br>

    <!-- If we're an Engine, display the Engine info and setup link -->
    <% if (isEngine) { %>
    <div style="border:1px solid black; width:50%; height:20%; background-image:url(images/formback.gif); background-repeat:repeat-x repeat-y; margin: 0 auto;">
      <div style="padding:20px; margin: 0 auto;">
        <%= msg.getString("ID_ENGINE_MESSAGE")%><br><br>
      </div>
     </div>
    <% } %>

    <br><br>

     <div style="width:50%; margin: 0 auto;">
       <div align="left"><strong>Guanxi@<%= siteMsg.getString("ID_INSTITUTION")%></strong></div>
     </div>
  </body>
</html>
