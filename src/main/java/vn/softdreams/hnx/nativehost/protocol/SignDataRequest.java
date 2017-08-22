package vn.softdreams.hnx.nativehost.protocol;

import javax.xml.bind.annotation.XmlElement;

/**
 * Created by chen on 7/11/2017.
 */
public class SignDataRequest extends NativeRequest {

    @XmlElement(name = "data")
    private String data;

    public String getDescription() {
        return "SignDataRequest";
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }
}
