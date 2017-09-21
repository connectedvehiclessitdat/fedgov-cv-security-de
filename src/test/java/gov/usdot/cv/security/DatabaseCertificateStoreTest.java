package gov.usdot.cv.security;

import static org.junit.Assert.*;

import java.util.Properties;

import gov.usdot.cv.resources.PrivateTestResourceLoader;
import gov.usdot.cv.security.CertificateLoader;
import gov.usdot.cv.security.DatabaseCertificateStore;
import gov.usdot.cv.security.cert.CertificateManager;
import gov.usdot.cv.security.crypto.CryptoProvider;
import gov.usdot.cv.security.util.UnitTestHelper;

import org.apache.log4j.Logger;
import org.junit.BeforeClass;
import org.junit.Test;

import com.deleidos.rtws.commons.config.RtwsConfig;

public class DatabaseCertificateStoreTest {

	static final private boolean isDebugOutput = false;
	private static final Logger log = Logger.getLogger(DatabaseCertificateStoreTest.class);
	
	private static final String certsFolder = "/etc/certs/";
	private static final String caCert = "ca.cert";
	private static final String raCert = "ra.cert";
	private static final String selfCert = "sdw.crt";
	private static final String selfCertKey = "sdw_key.txt";

	@SuppressWarnings("deprecation")
//	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		UnitTestHelper.initLog4j(isDebugOutput);
		String basedir = System.getProperty("basedir", ".");
		Properties testProperties = System.getProperties();
		testProperties.setProperty("RTWS_CONFIG_DIR", basedir + "/../commons-systems/src/systems/com.deleidos.rtws.localhost");
		System.setProperties(testProperties);
		RtwsConfig config = RtwsConfig.getInstance();
		config.setProperty("h2.app.connection.password", 
				PrivateTestResourceLoader.getProperty("@security-de/route.intersection.sit.data.test.password@"));
		config.setProperty("h2.dim.connection.url", "jdbc:h2:tcp://54.81.221.229:8161/commondb;SCHEMA_SEARCH_PATH=DIMENSIONS;MULTI_THREADED=1;MAX_OPERATION_MEMORY=268435456");
		config.setProperty("h2.app.connection.url", "jdbc:h2:tcp://54.81.221.229:8161/commondb;SCHEMA_SEARCH_PATH=APPLICATION;MULTI_THREADED=1;MAX_OPERATION_MEMORY=268435456");

		CryptoProvider.initialize();
	}
	
	// The unit test below can be used to add or replace Self certificate in the database
	@Test  @org.junit.Ignore
	public void loadCertificate() throws Exception {
		CertificateLoader.load("Self", certsFolder + selfCert, certsFolder + selfCertKey );
	}

	@Test @org.junit.Ignore
	public void testLoad() throws Exception {
		CertificateManager.clear();
		CertificateLoader.delete();
		
		assertNull("Initially thre is no CA cert", CertificateManager.get("CA"));
		assertNull("Initially thre is no RA cert", CertificateManager.get("RA"));
		assertNull("Initially thre is no Self cert", CertificateManager.get("Self"));
		
		try {
			CertificateLoader.load("CA", certsFolder + caCert, null);
		} catch (Exception ex) {
			log.debug("Couldn't load CA certificate. Reason: " + ex.getMessage(), ex);
			assertTrue("Loading CA cert was successful", false);
		}
		
		try {
			CertificateLoader.load("RA", certsFolder + raCert, null);
		} catch (Exception ex) {
			log.debug("Couldn't load RA certificate. Reason: " + ex.getMessage(), ex);
			assertTrue("Loading RA cert was successful", false);
		}

		DatabaseCertificateStore.refreshIntervalInMinutes = 1;
		DatabaseCertificateStore.initialize();
		
		Thread.sleep(1000);
		
		assertNotNull("After initialize there is CA cert", CertificateManager.get("CA"));
		assertNotNull("After initialize there is RA cert", CertificateManager.get("RA"));
		assertNull("After initialize there is no Self cert", CertificateManager.get("Self"));
		
		try {
			CertificateLoader.load("Self", certsFolder + selfCert, certsFolder + selfCertKey );
		} catch (Exception ex) {
			log.debug("Couldn't load Self certificate. Reason: " + ex.getMessage(), ex);
			assertTrue("Loading Self cert was successful", false);
		}
		
		Thread.sleep(65*1000);
		
		assertNotNull("After reload there is CA cert", CertificateManager.get("CA"));
		assertNotNull("After reload there is RA cert", CertificateManager.get("RA"));
		assertNotNull("After reload there is Self cert", CertificateManager.get("Self"));
		
		CertificateManager.clear();
		DatabaseCertificateStore.dispose();
	}
	
}
