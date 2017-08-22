package vn.softdreams.hnx.nativehost.protocol;

import javax.xml.bind.annotation.XmlElement;

/**
 * Created by chen on 7/11/2017.
 */
public class GetCertificateResponse extends NativeResponse {
    @XmlElement(name = "message")
    private String message;

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}
