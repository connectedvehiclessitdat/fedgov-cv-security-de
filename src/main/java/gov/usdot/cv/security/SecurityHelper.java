package gov.usdot.cv.security;

import gov.usdot.cv.security.cert.Certificate;
import gov.usdot.cv.security.cert.CertificateException;
import gov.usdot.cv.security.cert.CertificateManager;
import gov.usdot.cv.security.cert.FileCertificateStore;
import gov.usdot.cv.security.crypto.CryptoException;
import gov.usdot.cv.security.crypto.CryptoProvider;
import gov.usdot.cv.security.msg.IEEE1609p2Message;

import java.io.IOException;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Logger;

public class SecurityHelper {

	private static final Logger logger = Logger.getLogger(SecurityHelper.class);
	
	public static final int DEFAULT_PSID = 0x2fe1;
	
	private static boolean isSecurityInitialized = false;
	
	public static synchronized void initSecurity() {
		if ( !isSecurityInitialized ) {
			try {
				CryptoProvider.initialize();
				DatabaseCertificateStore.initialize();
				isSecurityInitialized = true;
			} catch (Exception e) {
				logger.error("Failed to initialize security " + e.toString(), e);
			}
		}
	}
	
	public static synchronized void disposeSecurity() {
		if ( !isSecurityInitialized ) {
			DatabaseCertificateStore.dispose();
			isSecurityInitialized = false;
		}
	}
	
	public static byte[] registerCert(byte[] certBytes, CryptoProvider cryptoProvider) throws CertificateException {
		Certificate cert = Certificate.fromBytes(cryptoProvider, certBytes);
		CertificateManager.put(cert.getCertID8(), cert);
		return cert.getCertID8();
	}
	
	public static byte[] encrypt(byte[] message, byte[] certID8, CryptoProvider cryptoProvider, int psid) {
		if ( certID8 != null ) {
			try {
				IEEE1609p2Message msg1609p2 = new IEEE1609p2Message(cryptoProvider);
				msg1609p2.setPSID(psid);
			
				logger.debug("Encrypting message for recipient: " + Hex.encodeHexString(certID8));
				return msg1609p2.encrypt(message, certID8);
			} catch (Exception ex) {
				logger.error("Couldn't encrypt message. Reason: " + ex.getMessage(), ex);
			}
		}
		return message;
	}
	
	public static byte[] decrypt(byte[] message, CryptoProvider cryptoProvider) {
		try {
			IEEE1609p2Message msg1609p2 = IEEE1609p2Message.parse(message, cryptoProvider);
			assert(msg1609p2 != null);
			return msg1609p2.getPayload();
		} catch (Exception ex) {
			logger.error("Couldn't decrypt message. Reason: " + ex.getMessage(), ex);
		}
		return null;
	}
	
	public static void loadCertificates(SecureConfig config) throws DecoderException, CertificateException, IOException, CryptoException {
		CertificateManager.clear();
		CryptoProvider cryptoProvider = new CryptoProvider();
		if (config.secure.certs != null) {
			for ( SecureConfig.CertEntry cert : config.secure.certs ) {
				if ( cert.key == null )
					FileCertificateStore.load(cryptoProvider, cert.name, cert.path);
				else
					FileCertificateStore.load(cryptoProvider, cert.name, cert.path, cert.key);
			}
		}
	}
}
