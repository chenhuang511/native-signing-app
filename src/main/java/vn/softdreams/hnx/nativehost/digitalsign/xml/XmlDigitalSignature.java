/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package vn.softdreams.hnx.nativehost.digitalsign.xml;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.StringReader;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignatureProperties;
import javax.xml.crypto.dsig.SignatureProperty;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.xml.security.utils.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

public class XmlDigitalSignature {

    private String createSignedFilePath(File srcFile) {
        String path = srcFile.getAbsolutePath();
        int index = path.lastIndexOf(".");
        String signedFileName = path.substring(0, index) + "-signed";
        String ext = path.substring(index, path.length());
        return signedFileName + ext;
    }

    public String performSign(File srcFile, X509Certificate cert, PrivateKey key) throws Exception {
        byte[] dataFile = FileUtils.readFileToByteArray(srcFile);
        String signedFile = createSignedFilePath(srcFile);

        DocumentBuilderFactory dbFactory
                = DocumentBuilderFactory.newInstance();
        dbFactory.setNamespaceAware(true);
        Document doc = dbFactory.newDocumentBuilder().parse(new ByteArrayInputStream(dataFile));
        // prepare signature factory
        String providerName = System.getProperty(
                "jsr105Provider",
                "org.jcp.xml.dsig.internal.dom.XMLDSigRI");
        final XMLSignatureFactory sigFactory
                = XMLSignatureFactory.getInstance(
                "DOM",
                (Provider) Class.forName(providerName).newInstance());

        Node sigParent = doc.getDocumentElement();
        String referenceURI = ""; // Empty string means whole document
        List transforms = Collections.singletonList(
                sigFactory.newTransform(
                        Transform.ENVELOPED,
                        (TransformParameterSpec) null));
        // Create a Reference to the enveloped document
        Reference ref = sigFactory.newReference(referenceURI,
                sigFactory.newDigestMethod(
                        DigestMethod.SHA1, null),
                transforms, null, null);
        // Create the SignedInfo
        SignedInfo signedInfo = sigFactory.newSignedInfo(
                sigFactory.newCanonicalizationMethod(
                        CanonicalizationMethod.INCLUSIVE,
                        (C14NMethodParameterSpec) null),
                sigFactory.newSignatureMethod(
                        SignatureMethod.RSA_SHA1,
                        null),
                Collections.singletonList(ref));

        // Create the SignedInfo.
        KeyInfoFactory keyInfoFactory = sigFactory.getKeyInfoFactory();
        List x509Content = new ArrayList();
        x509Content.add(cert);

        X509Data xd = keyInfoFactory.newX509Data(x509Content);
        KeyInfo keyInfo = keyInfoFactory.newKeyInfo(Collections.singletonList(xd));

        DOMSignContext dsc = new DOMSignContext(key, sigParent);

        XMLSignature signature = sigFactory.newXMLSignature(signedInfo, keyInfo);
        signature.sign(dsc);

        Transformer trans = TransformerFactory.newInstance().newTransformer();
        StreamResult res = new StreamResult(new FileOutputStream(signedFile));
        trans.transform(new DOMSource(doc), res);
        return signedFile;
    }

    public String performSign(File srcFile, Certificate[] chain, PrivateKey key) throws Exception {
        byte[] dataFile = FileUtils.readFileToByteArray(srcFile);
        String signedFile = createSignedFilePath(srcFile);

        DocumentBuilderFactory dbFactory
                = DocumentBuilderFactory.newInstance();
        dbFactory.setNamespaceAware(true);
        Document doc = dbFactory.newDocumentBuilder().parse(new ByteArrayInputStream(dataFile));
        // prepare signature factory
        String providerName = System.getProperty(
                "jsr105Provider",
                "org.jcp.xml.dsig.internal.dom.XMLDSigRI");
        final XMLSignatureFactory sigFactory
                = XMLSignatureFactory.getInstance(
                        "DOM",
                        (Provider) Class.forName(providerName).newInstance());

        Node sigParent = doc.getDocumentElement();
        String referenceURI = ""; // Empty string means whole document
        List transforms = Collections.singletonList(
                sigFactory.newTransform(
                        Transform.ENVELOPED,
                        (TransformParameterSpec) null));
        // Create a Reference to the enveloped document
        Reference ref = sigFactory.newReference(referenceURI,
                sigFactory.newDigestMethod(
                        DigestMethod.SHA1, null),
                transforms, null, null);
        // Create the SignedInfo
        SignedInfo signedInfo = sigFactory.newSignedInfo(
                sigFactory.newCanonicalizationMethod(
                        CanonicalizationMethod.INCLUSIVE,
                        (C14NMethodParameterSpec) null),
                sigFactory.newSignatureMethod(
                        SignatureMethod.RSA_SHA1,
                        null),
                Collections.singletonList(ref));

        // Create the SignedInfo.
        KeyInfoFactory keyInfoFactory = sigFactory.getKeyInfoFactory();
        List x509Content = new ArrayList();
        x509Content.addAll(Arrays.asList(chain));

        X509Data xd = keyInfoFactory.newX509Data(x509Content);
        KeyInfo keyInfo = keyInfoFactory.newKeyInfo(Collections.singletonList(xd));

        DOMSignContext dsc = new DOMSignContext(key, sigParent);

        XMLSignature signature = sigFactory.newXMLSignature(signedInfo, keyInfo);
        signature.sign(dsc);

        Transformer trans = TransformerFactory.newInstance().newTransformer();
        StreamResult res = new StreamResult(new FileOutputStream(signedFile));
        trans.transform(new DOMSource(doc), res);
        return signedFile;
    }
}
