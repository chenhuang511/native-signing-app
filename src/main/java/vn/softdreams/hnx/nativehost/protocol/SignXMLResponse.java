package vn.softdreams.hnx.nativehost.protocol;

import javax.xml.bind.annotation.XmlElement;

/**
 * Created by chen on 7/13/2017.
 */
public class SignXMLResponse extends NativeResponse {
    @XmlElement(name = "signedFile")
    private String signedFile;

    public String getSignedFile() {
        return signedFile;
    }

    public void setSignedFile(String signedFile) {
        this.signedFile = signedFile;
    }
}
