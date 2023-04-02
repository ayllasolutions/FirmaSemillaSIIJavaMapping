package com.util.firma.x509;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.StringWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyException;

import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.KeyStore;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.keyinfo.X509IssuerSerial;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;
import javax.xml.crypto.dsig.*;
import com.sap.aii.mapping.api.AbstractTrace;
import com.sap.aii.mapping.api.AbstractTransformation;
import com.sap.aii.mapping.api.StreamTransformationException;
import com.sap.aii.mapping.api.TransformationInput;
import com.sap.aii.mapping.api.TransformationOutput;
import com.sap.security.api.ssf.ISsfProfile;
import com.sap.aii.af.service.resource.*;
import com.sap.aii.security.lib.*;



import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import java.security.InvalidKeyException;

import java.security.SignatureException;
import java.security.UnrecoverableEntryException;



import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerFactoryConfigurationError;




public class XmlDigitalX509Signature extends AbstractTransformation {
	static AbstractTrace log = null;
	
	@Override
	public void transform(TransformationInput inptS, TransformationOutput outS) throws StreamTransformationException {
		log = this.getTrace();
		log.addDebugMessage("@@@@ START JVN");
		
		String keyView 	= ""; //Nombre de la vista de certificado en el almacen de certificados digitales de SAP PI/PO/XI 
		String keyEntry = ""; //Nombre de la entrada de certificado en el almacen de certificados digitales de SAP PI/PO/XI
		String passwd 	= ""; //Password de certificado en el almacen de certificados digitales de SAP PI/PO/XI
		
		
		try {
			
			//Instacia de la clase ISsProfile perteneciente al namespace com.sap.security.api.ssf
			ISsfProfile isP = getCertProfile(keyView,keyEntry,passwd);
			
			
			//Instacioa de la clase XMLSignatureFactory perteneciente al namespace de criptografia javax.xml.crypto.dsig
			XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
			
			// Crea una referencia para el envoltorio del documento
			Reference ref = fac.newReference
			 ("", fac.newDigestMethod(DigestMethod.SHA1, null),
			  Collections.singletonList
			   (fac.newTransform
			    (Transform.ENVELOPED, (TransformParameterSpec) null)),
			     null, null);
			
			// Crea la informacion para la firma
			SignedInfo si = fac.newSignedInfo
			 (fac.newCanonicalizationMethod
			  (CanonicalizationMethod.INCLUSIVE,
			   (C14NMethodParameterSpec) null),
			    fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null),
			     Collections.singletonList(ref));
			
			// Crea el KeyInfo que contiene la X509Data.
			KeyInfoFactory kif = fac.getKeyInfoFactory();
			
			//Lista de los datos que van sobre Xdata 
			List x509Content = new ArrayList();
			x509Content.add(isP.getCertificate().getSubjectX500Principal().getName());
			x509Content.add(isP.getCertificate());
			
			//Obtiene la llave publica
			PublicKey pk = isP.getCertificate().getPublicKey();
			
			//Asigna el contenido x509data al tag XML X509Data
			X509Data xd = kif.newX509Data(x509Content);
			
			//Asigna la llave publica al tag xml KeyValue
			KeyValue kv = kif.newKeyValue(pk);
			
			// Asigna toda la informacion anterior al tag XML KeyInfoContent
			List KeyInfoContent = new ArrayList();
			KeyInfoContent.add(kv);
			KeyInfoContent.add(xd);

			
			//Asigna el KeyInfoContent al tag XML KeyInfo
			KeyInfo ki = kif.newKeyInfo(KeyInfoContent);
						
			
			// Crea una instacion de document builder y le asigna el payload recibido desde R3 o S4 (Amnas son versiones de SAP ERP)
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			Document doc = dbf.newDocumentBuilder().parse(inptS.getInputPayload().getInputStream());
			
			
			TransformerFactory tf2 = TransformerFactory.newInstance();
			Transformer trans2 = tf2.newTransformer();
			trans2.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");

			// Escribe el contenido en XML String
			StringWriter writer2 = new StringWriter();
			trans2.transform(new DOMSource(doc), new StreamResult(writer2));
			
			
			
		    DocumentBuilderFactory docFactorynew2 = DocumentBuilderFactory.newInstance();
		    DocumentBuilder finalDocbuilder2 = docFactorynew2.newDocumentBuilder();
		    InputStream inputStream2 = new    ByteArrayInputStream(writer2.getBuffer().toString().trim().getBytes());
		    Document docSemilla = finalDocbuilder2.parse(inputStream2);

			
			

			//Arma la primera parte del XML que se debe firmar, en base a la "especificacion"(xd) del SII
			NodeList root = docSemilla.getChildNodes();
			NodeList gettokens = root.item(0).getChildNodes();		
			String semillita = writer2.getBuffer().toString().trim();
			
			//Busca dentro del payload, el valor de la semilla para luego asignarlo al XML que se enviara a firmar.
			//Esto se podria haber hecho con las herramientas que provee java para la lectura de archivos XML, pero por algun motivo desconocido
			//al desplegar la solucion, esto no funciona. Por eso se hizo con este metodo "carretero"(XD).
			semillita = semillita.substring(196,semillita.length());
			semillita = semillita.substring(0, 12);
			
			String cemillaformada = semillita;
			
			DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilder docBuilder = docFactory.newDocumentBuilder();
			Document newdoc = docBuilder.newDocument();
			Element rootElement = newdoc.createElement("getToken");
			newdoc.appendChild(rootElement);
			// items
			Element item = newdoc.createElement("item");
			rootElement.appendChild(item);
			Element semillana = newdoc.createElement("Semilla");
			
			// Semilla,se agrega el valor de la semilla devuelto por el WS de el SII
			semillana.setTextContent(cemillaformada);
			item.appendChild(semillana);
			
			DOMSignContext dsc = new DOMSignContext
				    (getCertProfile(keyView,keyEntry,passwd).getPrivateKey(), newdoc.getDocumentElement());
			
			
			// Crea la firma XML
			XMLSignature signature = fac.newXMLSignature(si, ki);
			
			//Se debe mandar a firmar el xml correcto
			signature.sign(dsc);
			
			
			TransformerFactory tf1 = TransformerFactory.newInstance();
			Transformer transformer1 = tf1.newTransformer();
			transformer1.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
			StringWriter writer = new StringWriter();
			transformer1.transform(new DOMSource(newdoc), new StreamResult(writer));
			String output = writer.getBuffer().toString().replaceAll("\n|\r", "");
			
			//Este es el documento final ya firmado y que nos servira para obtener el bendito token del SII
			String docFinalXML = "<?xml version=\"1.0\"?><ns1:MT_TokenDTE_ECC_Req xmlns:ns1=\"urn:Chilexpress.cl:SII/DocumentoTributarioElectronico:EstadoDTE:ECC\"><getToken><Semilla><![CDATA[" + output + "]]></Semilla></getToken></ns1:MT_TokenDTE_ECC_Req>";
			
		    DocumentBuilderFactory docFactorynew = DocumentBuilderFactory.newInstance();
		    DocumentBuilder finalDocbuilder = docFactorynew.newDocumentBuilder();
		    InputStream inputStream = new    ByteArrayInputStream(docFinalXML.getBytes());
		    Document docfinal = finalDocbuilder.parse(inputStream);
			
			
			
			
			OutputStream os = outS.getOutputPayload().getOutputStream();
			TransformerFactory tf = TransformerFactory.newInstance();
			Transformer trans = tf.newTransformer();
			trans.transform(new DOMSource(docfinal), new StreamResult(os));
			
			
		} catch (IOException e) {
			e.printStackTrace();

		} catch (SAXException e) {
			
			e.printStackTrace();
		} catch (ParserConfigurationException e) {
			
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			
			e.printStackTrace();
		} catch (MarshalException e) {
			
			e.printStackTrace();
		} catch (XMLSignatureException e) {
			
			e.printStackTrace();
		} catch (TransformerException e) {
			
			e.printStackTrace();
		} catch (KeyException e) {
			
			e.printStackTrace();
		}
		
	}

	private static ISsfProfile getCertProfile(String alias, String entry,String pwd) throws StreamTransformationException {

		KeyStoreManager managerPriviliged;

		try {

			managerPriviliged = (KeyStoreManager) SAPSecurityResources.getInstance().getKeyStoreManager(com.sap.aii.security.lib.PermissionMode.SYSTEM_LEVEL);

		} catch (KeyStoreException e) {
			throw new StreamTransformationException("SAPSecurityResources", e);
		}

		KeyStore keyStore;


		try {
			keyStore = managerPriviliged.getKeyStore(alias);

		} catch (KeyStoreException e) {
			throw new StreamTransformationException("managerPriviliged.getKeyStore " + alias, e);
		}

		ISsfProfile profile = null;
		try {
			
			profile = (ISsfProfile)managerPriviliged.getISsfProfile(keyStore, entry, null);

		} catch (KeyStoreException e) {
			throw new StreamTransformationException(
					"Failed to load SsfProfileKeyStore " + alias + " " + entry, e);
		}
		return profile;
	}
	
}
