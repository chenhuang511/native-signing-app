package vn.softdreams.hnx.nativehost.digitalsign;

import org.apache.log4j.Logger;
import org.json.JSONArray;
import org.json.JSONObject;
import vn.softdreams.hnx.nativehost.digitalsign.xml.XmlDigitalSignature;
import vn.softdreams.hnx.nativehost.gui.SelectCertificate;

import javax.swing.*;
import javax.swing.filechooser.FileFilter;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.io.File;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Created by chen on 7/11/2017.
 */
public class CryptoUtils {

    private static final Logger logger = Logger.getLogger(CryptoUtils.class);

    public static String getCertificates() throws Exception {
        X509Certificate selectedCert = (X509Certificate) selectCert().get("cert");
        JSONObject jsonObj = new JSONObject();
//        jsonObj.put("SubjectDN", selectedCert.getSubjectDN().getName());
//        jsonObj.put("IssuerDN", selectedCert.getIssuerDN().getName());
        jsonObj.put("Serial", selectedCert.getSerialNumber().toString(16));
//        jsonObj.put("Expires", selectedCert.getNotAfter());
        JSONArray jsonArray = new JSONArray();
        jsonArray.put(jsonObj);

        JSONObject jsonObjSuccess = new JSONObject();
        jsonObjSuccess.put("success", true);
        jsonObjSuccess.put("certificate", jsonArray);

        return jsonObjSuccess.toString();
    }

    private static Map<String, Object> selectCert() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("Windows-MY", "SunMSCAPI");
        keyStore.load(null, null);
        Enumeration<String> al = keyStore.aliases();


        List<X509Certificate> certs = new ArrayList<>();
        List<PrivateKey> keys = new ArrayList<>();
        Integer i = 0;
        while (al.hasMoreElements()) {
            i++;
            String alias = al.nextElement();
            X509Certificate cert = (X509Certificate) keyStore
                    .getCertificate(alias);
            certs.add(cert);
            PrivateKey key = (PrivateKey) keyStore.getKey(alias, null);
            if (key != null)
                logger.info("get private key, key's format: " + key.getAlgorithm());
            keys.add(key);
        }
        logger.info("Display certificate select dialog");
        SelectCertificate selector = new SelectCertificate(null, true, certs);
        selector.setVisible(true);
        Map<String, Object> map = new HashMap<>();
        map.put("cert", selector.getSelectedCert());
        map.put("key", keys.get(selector.getSelectedIndex()));
        logger.info("Selected cert: " + selector.getSelectedCert().getSubjectDN().getName());
        return map;
    }

    public static String signData(byte[] data) throws Exception {
//        Signature signature = Signature.getInstance("SHA1withRSA");
//        signature
        return "";
    }

    public static String signXML() throws Exception {
        logger.info("Begin Sign XML");
        File selectedFile = null;
        JSONObject jsonObjSuccess = new JSONObject();
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setCurrentDirectory(new File(System.getProperty("user.home")));
        FileFilter filter = new FileNameExtensionFilter("XML", new String[]{"xml"});
        fileChooser.setFileFilter(filter);
        int result = fileChooser.showOpenDialog(null);
        if (result == JFileChooser.APPROVE_OPTION) {
            selectedFile = fileChooser.getSelectedFile();
            XmlDigitalSignature xmlSigner = new XmlDigitalSignature();
            Map map = selectCert();
            String signedFile = xmlSigner.performSign(selectedFile, (X509Certificate) map.get("cert"), (PrivateKey) map.get("key"));
            jsonObjSuccess.put("success", true);
            jsonObjSuccess.put("signedFile", signedFile);
            logger.info("Finish sign XML, signed file path: " + signedFile);
        } else {
            jsonObjSuccess.put("success", false);
            logger.info("Finish sign XML, fail");
        }
        return jsonObjSuccess.toString();
    }

    public static String signPDF(String filePath) throws Exception {
        return "";
    }

    private static String getThumbPrint(X509Certificate cert)
            throws NoSuchAlgorithmException, CertificateEncodingException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] der = cert.getEncoded();
        md.update(der);
        byte[] digest = md.digest();
        return hexify(digest);
    }

    private static String hexify(byte bytes[]) {

        char[] hexDigits = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a',
                'b', 'c', 'd', 'e', 'f'};

        StringBuffer buf = new StringBuffer(bytes.length * 2);

        for (int i = 0; i < bytes.length; ++i) {
            buf.append(hexDigits[(bytes[i] & 0xf0) >> 4]);
            buf.append(hexDigits[bytes[i] & 0x0f]);
        }

        return buf.toString();
    }
}
