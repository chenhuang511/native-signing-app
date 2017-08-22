package vn.softdreams.hnx.nativehost.protocol;

import javax.xml.bind.annotation.XmlElement;

public class NativeResponse {

	@XmlElement(name = "type")
	private String type;
	
	public NativeResponse() {
		super();
	}

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}
}