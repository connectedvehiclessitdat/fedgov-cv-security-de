package gov.usdot.cv.security;

import gov.usdot.cv.security.cert.Certificate;
import gov.usdot.cv.security.cert.CertificateManager;
import gov.usdot.cv.security.crypto.CryptoProvider;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.apache.log4j.Logger;

public class DatabaseCertificateStore {
	
	private static final Logger log = Logger.getLogger(DatabaseCertificateStore.class);
	
	static int refreshIntervalInMinutes = 30;
	
	private static MessageDigest digest;
	
	private static ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

	public static synchronized void initialize()  throws Exception {
		if (digest == null) {
			digest = MessageDigest.getInstance("SHA-256");
			loadStore();
			scheduler.scheduleAtFixedRate(new PeriodicCertificateLoader(), refreshIntervalInMinutes, refreshIntervalInMinutes, TimeUnit.MINUTES);
		}
	}
	
	public static synchronized void dispose() {
		scheduler.shutdownNow();
	}

	private static void loadStore() throws Exception {
		SecurityDAO dao = SecurityDAO.getInstance();
		
		List<CertContainer> allCerts = dao.getAllCertificates();
		CryptoProvider cryptoProvider = new CryptoProvider();
		for (CertContainer certContainer : allCerts) {
			Certificate cert = certContainer.certKeyBytes == null ?
					Certificate.fromBytes(cryptoProvider, certContainer.certBytes) :
					Certificate.fromBytes(cryptoProvider, certContainer.certBytes, certContainer.certKeyBytes);
					
			Certificate currentCert = CertificateManager.get(certContainer.name);
			if ( currentCert == null || !Arrays.equals(currentCert.getBytes(), cert.getBytes())) {
				CertificateManager.put(certContainer.name, cert);
				log.debug("Updated certificate with name: " + certContainer.name);
			}
		}
	}

	private static class PeriodicCertificateLoader implements Runnable {
		@Override
		public void run() {
			log.debug("Refreshing certificate store");
			try {
				loadStore();
			} catch (Exception ex) {
				log.error("Couldn't refresh certificate store. Reason: " + ex.getMessage(), ex);
			}
		}
	}

}
