<? include "messages.php"; ?>
<html>
  <head><title>Shibboleth Error</title></head>
  <body>
  	<center><strong><? echo $errorMessages[$_GET[errorCode]]; ?></strong></center>
  </body>
</html>
