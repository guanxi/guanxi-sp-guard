<%@ page contentType="application/xml; charset=UTF-8" %>
<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Name="${entityID}">
    <EntityDescriptor entityID="${entityID}">
        <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <KeyDescriptor>
                <ds:KeyInfo>
                    <ds:X509Data>
                        <ds:X509Certificate>
                            ${signingCertificate}
                        </ds:X509Certificate>
                    </ds:X509Data>
                </ds:KeyInfo>
            </KeyDescriptor>
            <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:1.0:profiles:browser-post" 
                                      Location="${acsURL}" index="1"/>
        </SPSSODescriptor>
    </EntityDescriptor>
</EntitiesDescriptor>