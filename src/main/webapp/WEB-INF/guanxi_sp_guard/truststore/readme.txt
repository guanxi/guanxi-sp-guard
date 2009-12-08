This is the Guard's truststore directory. If the truststore named in the file:
WEB-INF/guanxi_sp_guard/config/guanxi-sp-guard.xml : TrustStore
does not exist, the Guard will create it automatically when it starts up.
The truststore is used to store the Engine's certificate when the Guard
is communicating with it via HTTPS.