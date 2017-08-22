package vn.softdreams.hnx.nativehost.main;

import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.log4j.Logger;
import vn.softdreams.hnx.nativehost.digitalsign.CryptoUtils;
import vn.softdreams.hnx.nativehost.protocol.GetCertificateResponse;
import vn.softdreams.hnx.nativehost.protocol.NativeRequest;
import vn.softdreams.hnx.nativehost.protocol.NativeResponse;
import vn.softdreams.hnx.nativehost.protocol.SignXMLResponse;
import vn.softdreams.hnx.nativehost.utils.Constants;

public class Main {

    private static Logger logger = Logger.getLogger(Main.class);

    public static void main(String[] args)  {
        try {
            logger.info("START");
            // Read message
            String requestJson = readMessage(System.in);

            ObjectMapper mapper = new ObjectMapper();
            NativeRequest request = mapper.readValue(requestJson, NativeRequest.class);
            String responseJson = "";
            String type = request.getType();
//            String type = "getCert";
            logger.info(type);
            switch (type) {
                case Constants.TYPE_GET_CERT:
                    responseJson = getCertificates(mapper);
                    break;
                case Constants.TYPE_SIGN_DATA:
                    break;
                case Constants.TYPE_SIGN_XML:
                    responseJson = signXML(mapper);
                    break;
                default:
                    responseJson = getCertificates(mapper);
                    break;
            }

            // Send response message back
            sendMessage(responseJson);
            logger.info("DONE");
            System.exit(0);
        } catch (Exception e) {
            logger.error(e.getMessage());
            System.exit(0);
        }
    }

    private static String signXML(ObjectMapper mapper) throws Exception {
        SignXMLResponse response = new SignXMLResponse();
        response.setType("signXML");
        response.setSignedFile(CryptoUtils.signXML());
        return mapper.writeValueAsString(response);
    }

    private static String getCertificates(ObjectMapper mapper) throws Exception {
        // Process request...
        GetCertificateResponse response = new GetCertificateResponse();
        response.setType("getCert");
        response.setMessage(CryptoUtils.getCertificates());
        return mapper.writeValueAsString(response);
    }

    private static String readMessage(InputStream in) throws IOException {
        byte[] b = new byte[4];
        in.read(b); // Read the size of message

        int size = getInt(b);

        if (size == 0) {
            throw new InterruptedIOException("Blocked communication");
        }

        b = new byte[size];
        in.read(b);

        return new String(b, "UTF-8");
    }

    private static void sendMessage(String message) throws IOException {
        System.out.write(getBytes(message.length()));
        System.out.write(message.getBytes("UTF-8"));
        System.out.flush();
    }

    public static int getInt(byte[] bytes) {
        return (bytes[3] << 24) & 0xff000000 | (bytes[2] << 16) & 0x00ff0000 | (bytes[1] << 8) & 0x0000ff00
                | (bytes[0] << 0) & 0x000000ff;
    }

    public static byte[] getBytes(int length) {
        byte[] bytes = new byte[4];
        bytes[0] = (byte) (length & 0xFF);
        bytes[1] = (byte) ((length >> 8) & 0xFF);
        bytes[2] = (byte) ((length >> 16) & 0xFF);
        bytes[3] = (byte) ((length >> 24) & 0xFF);
        return bytes;
    }
}
