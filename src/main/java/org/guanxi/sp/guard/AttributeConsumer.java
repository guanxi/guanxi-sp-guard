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
//: The Initial Developer of the Original Code is Alistair Young alistair@smo.uhi.ac.uk.
//: Portions created by SMO WWW Development Group are Copyright (C) 2005 SMO WWW Development Group.
//: All Rights Reserved.
//:
/* CVS Header
   $Id$
   $Log$
   Revision 1.1.1.1  2008/01/23 15:28:59  alistairskye
   Standalone Guard module

   Revision 1.12  2007/03/28 13:53:13  alistairskye
   Updated process() with bug fix for an attribute with no value.

   Revision 1.11  2007/01/24 10:59:25  alistairskye
   Updated process() to handle eduPersonScopedAffiliation. Now concatenates the Scope and value for the header.

   Revision 1.10  2007/01/05 20:20:23  alistairskye
   Fixed bug in process() that threw NPE if no attributes were coming from IdP

   Revision 1.9  2007/01/04 13:49:47  alistairskye
   Now parses SOAP and SAML Response instead of the Bag.
   Now adds attributes as convenience objects to the Bag.
   Now stores raw SAML in the Bag.
   Updated javadoc.

   Revision 1.8  2006/11/23 15:17:57  alistairskye
   Updated to use XMLBeans instead of org.guanxi.common.SOAPUtils for working with SOAP messages

   Revision 1.7  2006/07/25 14:22:29  alistairskye
   Updated to use new Log directory information

   Revision 1.6  2006/01/26 08:56:31  alistairskye
   Updated to use Logging.DEFAULT_SP_GUARD_CONFIG_FILE

   Revision 1.5  2006/01/21 18:35:47  alistairskye
   Modified to use Logging.DEFAULT_SP_LOG_DIR

   Revision 1.4  2005/09/22 08:33:15  alistairskye
   Changed initLogger to use Logging.DEFAULT_IDP_CONFIG_FILE

   Revision 1.3  2005/08/11 14:15:52  alistairskye
   Associates attributes with a session Pod

   Revision 1.2  2005/08/10 14:54:36  alistairskye
   Updated license

   Revision 1.1.1.1  2005/08/10 14:19:23  alistairskye
   Guanxi Service Provider

*/

package org.guanxi.sp.guard;

import org.guanxi.common.*;
import org.guanxi.common.definitions.Logging;
import org.guanxi.common.definitions.EduPerson;
import org.guanxi.xal.soap.EnvelopeDocument;
import org.guanxi.xal.soap.Header;
import org.guanxi.xal.saml_1_0.protocol.ResponseDocument;
import org.guanxi.xal.saml_1_0.assertion.AssertionType;
import org.guanxi.xal.saml_1_0.assertion.AttributeStatementType;
import org.guanxi.xal.saml_1_0.assertion.AttributeType;
import org.apache.log4j.xml.DOMConfigurator;
import org.apache.log4j.PatternLayout;
import org.apache.log4j.RollingFileAppender;
import org.apache.log4j.Logger;
import org.apache.xmlbeans.XmlObject;
import org.w3c.dom.NodeList;
import org.w3c.dom.Node;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletException;
import javax.servlet.ServletContext;
import java.io.*;

/**
 * The AttributeConsumer service is responsible for parsing the SAML Response that has been obtained
 * from an IdP by the Engine. The Engine will forward the IdP's SOAP reponse as-is to this service.
 * The Engine will also add a SOAP header of it's own, telling us which Guard session the attributes
 * contained in the SAML Response are for.
 *
 * <pre>
 * <Envelope>
 *   <Header>
 *     <GuanxiGuardSessionID>GUARD_-603305be:10fed31ab4c:-8000</GuanxiGuardSessionID>
 *   </Header>
 *   <Body>
 *     <samlp:Response>
 *       <samlp:Status />
 *       <saml:Assertion>
 *         <saml:Conditions />
 *         <saml:AttributeStatement>
 *           <saml:Subject />
 *           <saml:Attribute>
 *             <saml:AttributeValue />
 *           </saml:Attribute>
 *           ...
 *         </saml:AttributeStatement>
 *       </saml:Assertion>
 *     </samlp:Response>
 *   </Body>
 * </Envelope>
 * </pre>
 *
 * The AttributeConsumer service will load up the Pod previously created by the Podder service and add
 * the SAML Attributes to a Bag which it will place in the Pod. These are convenience objects for getting
 * hold of attributes without having to parse raw SAML.
 * If an application requires access to the full SAML Response it can parse the String representation of
 * the raw SAML that the AttributeConsumer services stores in the Bag.
 *
 * @author Alistair Young alistair@smo.uhi.ac.uk
 * @author Davide Zanatta davide.zanatta@gmail.com - bug fixing
 */
public class AttributeConsumer extends HttpServlet {
  /** Our logger */
  private static Logger log = Logger.getLogger(AttributeConsumer.class);

  public void init() throws ServletException {
    try {
      initLogger(getServletContext());
    }
    catch(GuanxiException ge) {
      throw new ServletException(ge);
    }
  }

  public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    process(request, response);
  }

  public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    process(request, response);
  }

  /**
   * Parses the incoming SOAP/SAML message, populates a Bag with convenience objects for accessing the SAML
   * attributes and puts the Bag in the specified session's Pod. The session is specified by the value of the
   * GuanxiGuardSessionID node in the SOAP header.
   *
   * @param request Standard HttpServletRequest
   * @param response Standard HttpServletResponse
   * @throws ServletException if an error occurs
   * @throws IOException if an error occurs
   */
  public void process(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    try {
      // Read the request into a String...
      InputStream in = request.getInputStream();
      BufferedReader buffer = new BufferedReader(new InputStreamReader(in));
      StringBuffer stringBuffer = new StringBuffer();
      String line = null;
      while ((line = buffer.readLine()) != null) {
        stringBuffer.append(line);
      }
      in.close();

      // ...and parse the SOAP message
      EnvelopeDocument soapDoc = EnvelopeDocument.Factory.parse(stringBuffer.toString());

      /* Get the GuanxiGuardSessionID SOAP header. This tells us which Guard session contains
       * the Pod to which we should attach this Bag of attributes.
       */
      Header header = soapDoc.getEnvelope().getHeader();
      String guanxiGuardSessionID = null;
      guanxiGuardSessionID = header.getDomNode().getFirstChild().getFirstChild().getNodeValue();

      // Get a SOAP message ready for sending back to the Engine
      EnvelopeDocument soapEnvelopeDoc = EnvelopeDocument.Factory.newInstance();
      soapEnvelopeDoc.addNewEnvelope();

      // If we can't find a GuanxiGuardSessionID, return an error to the Engine
      if (guanxiGuardSessionID == null) {
        soapEnvelopeDoc.save(response.getOutputStream());
        return;
      }

      // Now rake through the SOAP to find the SAML Response...
      NodeList nodes = soapDoc.getEnvelope().getBody().getDomNode().getChildNodes();
      Node samlResponseNode = null;
      for (int c=0; c < nodes.getLength(); c++) {
        samlResponseNode = nodes.item(c);
        if (samlResponseNode.getLocalName() != null) {
          if (samlResponseNode.getLocalName().equals("Response"))
            break;
        }
      }
      // ...and parse it
      ResponseDocument samlResponseDoc = ResponseDocument.Factory.parse(samlResponseNode);

      // Get a new Bag...
      Bag bag = new Bag();
      // ...and store the raw SAML Response in it as a String
      bag.setSamlResponse(samlResponseDoc.toString());

      // Grab the Assertions, if there are any...
      AssertionType[] assertions = samlResponseDoc.getResponse().getAssertionArray();
      if (assertions.length > 0) {
        // ...to get the AttributeStatement...
        AttributeStatementType[] attrStatements = assertions[0].getAttributeStatementArray();
        // ...and the corresponding attributes...
        AttributeType[] attributes = attrStatements[0].getAttributeArray();
        // ...adding them as convenience objects to the Bag
        for (int c=0; c < attributes.length; c++) {
          XmlObject[] obj = attributes[c].getAttributeValueArray();
          for (int cc=0; cc < obj.length; cc++) {
            if (attributes[c].getAttributeName().equals(EduPerson.EDUPERSON_SCOPED_AFFILIATION)) {
              String attrValue = obj[cc].getDomNode().getFirstChild().getNodeValue();
              attrValue += EduPerson.EDUPERSON_SCOPED_AFFILIATION_DELIMITER;
              attrValue += obj[cc].getDomNode().getAttributes().getNamedItem(EduPerson.EDUPERSON_SCOPED_AFFILIATION_SCOPE_ATTRIBUTE).getNodeValue();
              bag.addAttribute(attributes[c].getAttributeName(), attrValue);
            }
            else {
              if (obj[cc].getDomNode().getFirstChild() != null) {
                bag.addAttribute(attributes[c].getAttributeName(), obj[cc].getDomNode().getFirstChild().getNodeValue());
              }
            }
          }
        }
      }

      // Load up the specified session's Pod...
      Pod pod = (Pod)getServletContext().getAttribute(guanxiGuardSessionID);
      // ...and add the bag of attributes
      pod.setBag(bag);

      // Return success message to the Engine
      soapEnvelopeDoc.save(response.getOutputStream());
    }
    catch(Exception e) {
      log.error(e);
      throw new ServletException(e);
    }
  }

  private void initLogger(ServletContext context) throws GuanxiException {
    DOMConfigurator.configure(context.getRealPath(Logging.DEFAULT_SP_GUARD_CONFIG_FILE));

    PatternLayout defaultLayout = new PatternLayout(Logging.DEFAULT_LAYOUT);

    RollingFileAppender rollingFileAppender = new RollingFileAppender();
    rollingFileAppender.setName("GuanxiGuardAttributeConsumerService");
    try {
      rollingFileAppender.setFile(context.getRealPath(Logging.DEFAULT_SP_GUARD_LOG_DIR + "guanxi-sp-guard-attribute-consumer-service.log"), true, false, 0);
    }
    catch(IOException ioe) {
      throw new GuanxiException(ioe);
    }
    rollingFileAppender.setMaxFileSize("1MB");
    rollingFileAppender.setMaxBackupIndex(5);
    rollingFileAppender.setLayout(defaultLayout);

    log.removeAllAppenders();
    log.addAppender(rollingFileAppender);
    log.setAdditivity(false);
  }
}
