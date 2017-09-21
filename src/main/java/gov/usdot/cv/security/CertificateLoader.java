package gov.usdot.cv.security;

import java.io.File;
import java.io.IOException;
import java.sql.SQLException;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.FileUtils;

public class CertificateLoader {
	
	public static void load(String name, String certFileName, String certKeyFileName ) throws IOException, DecoderException, SQLException {
		load(SecurityDAO.getInstance(), name, certFileName, certKeyFileName);
	}
	
	public static void load(SecurityDAO dao, String name, String certFileName, String certKeyFileName ) throws IOException, DecoderException, SQLException {		
		boolean isBinaryFile = certFileName.toLowerCase().endsWith(".crt");
		byte[] certBytes = null;
		byte[] keyBytes = null;
		if ( isBinaryFile ) {
			certBytes = FileUtils.readFileToByteArray(new File(certFileName));
		} else {
			String certString = FileUtils.readFileToString(new File(certFileName));
			certString = certString.replaceAll(" ", "");
			certBytes = Hex.decodeHex(certString.toCharArray());
		}
		if ( certKeyFileName != null ) {
			String keyString = FileUtils.readFileToString(new File(certKeyFileName));
			keyString = keyString.replaceAll("([,]\\s+)?0x", "");
	    	keyBytes = Hex.decodeHex(keyString.toCharArray());
		}
		dao.addCertificate(name, certBytes, keyBytes);
	}
	
	static void delete() throws SQLException {
		SecurityDAO.deleteStore();
	}

	public static void main(String[] args) {

		if (args.length < 2 || args.length > 3) {
			System.err.println("CertificateLoader: Invalid arguments. Usage:");
			System.err.println("\t<NAME> <PATH_TO_CERTIFICATE> <OPTIONAL_CERTIFICATE_DECRYPTION_KEY>");
		} else {
			String name = args[0];
			String certFileName = args[1];
			String certKeyFileName = null;
			if (args.length == 3)
				certKeyFileName = args[2];
			
			try {
				load(name, certFileName, certKeyFileName);
			} catch ( Exception ex ) {
				System.err.println(String.format("Coulnd't load certificate %s from file '%s' with key '%s'",
						name, certFileName, certKeyFileName != null ? certKeyFileName : "<no key file>"));
			}
		}

	}
}
