package vn.softdreams.hnx.nativehost.protocol;

import javax.xml.bind.annotation.XmlElement;

public class NativeRequest {

	@XmlElement(name = "type")
	private String type;
	
	public NativeRequest() {
		super();
	}

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}
}
