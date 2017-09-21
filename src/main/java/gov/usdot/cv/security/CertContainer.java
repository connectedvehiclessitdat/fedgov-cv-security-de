package gov.usdot.cv.security;

public class CertContainer {

	public final String name;
	public final byte[] certBytes;
	public final byte[] certKeyBytes;
	
	public CertContainer(String name, byte[] certBytes, byte[] certKeyBytes){
		this.name = name;
		this.certBytes = certBytes;
		this.certKeyBytes = certKeyBytes;
	}
}
