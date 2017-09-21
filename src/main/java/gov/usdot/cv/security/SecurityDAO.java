package gov.usdot.cv.security;

import gov.usdot.cv.security.cert.Certificate;
import gov.usdot.cv.security.cert.CertificateException;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import javax.sql.DataSource;

import com.deleidos.rtws.commons.dao.source.H2DataSourceFactory;

public class SecurityDAO {
	
	private static final String CERTS_TABLE_NAME = "APPLICATION.CV_CERTIFICATES";
	private static final String REVOCATIONS_TABLE_NAME = "APPLICATION.CV_REVOKED_CERTIFICATES";
	
	private static final String LOAD_ORDEDER = "LOAD_ORDEDER";
	private static final String CERT_NAME = "CERT_NAME";
	private static final String CERT_BYTES = "CERT_BYTES";
	private static final String DECRYPTION_KEY = "DECRYPTION_KEY";
	
	private static final String CERT_ID = "CERT_ID";
	
	private static final String createStoreIfNeededSQL = "CREATE TABLE IF NOT EXISTS " + CERTS_TABLE_NAME + " ("
			+ LOAD_ORDEDER	 + " INT AUTO_INCREMENT, "
			+ CERT_NAME 	 + " VARCHAR(128) PRIMARY KEY, "
			+ CERT_BYTES	 + " BINARY(65536) NOT NULL, "
			+ DECRYPTION_KEY + " BINARY(256));";
	
	private static final String deleteCertsSQL = "DROP TABLE " + CERTS_TABLE_NAME + " ;";
	private static final String deleteRevocationsSQL = "DROP TABLE " + REVOCATIONS_TABLE_NAME + " ;";
	
	private static final String addCertificateSQL = "MERGE INTO " + CERTS_TABLE_NAME + " (" + CERT_NAME + ", " + CERT_BYTES + ", " + DECRYPTION_KEY + ") VALUES (?,?,?);";
	private static final String getCertNameSQL 	 = "SELECT * FROM " + CERTS_TABLE_NAME + " WHERE " + CERT_NAME + "=?;";
	private static final String getAllCertsSQL 	 = "SELECT * FROM " + CERTS_TABLE_NAME + " ORDER BY " + CERT_NAME + " ASC;";
	
	private static final String createRevocationsIfNeededSQL = "CREATE TABLE IF NOT EXISTS "+REVOCATIONS_TABLE_NAME+" (" + CERT_ID + " BINARY(8) PRIMARY KEY);";
	
	private static final String revokeCertificateSQL = "MERGE INTO " + REVOCATIONS_TABLE_NAME + " ( " + CERT_ID + " ) VALUES (?);";
	private static final String getAllRevocationsSQL = "SELECT * from " + REVOCATIONS_TABLE_NAME + ";";
	
	private PreparedStatement addCertificate;
	private PreparedStatement getCertByName;
	private PreparedStatement getAllCerts;
	private PreparedStatement revokeCertificate;
	private PreparedStatement getRevocations;
	
	private DataSource ds;
	
	private static volatile SecurityDAO instance = null;
	
	private SecurityDAO() throws SQLException {
		ds = H2DataSourceFactory.getInstance().getDataSource();

		Connection conn = ds.getConnection();
		PreparedStatement createStoreTable = conn.prepareStatement(createStoreIfNeededSQL);
		PreparedStatement createRevocationTable = conn.prepareStatement(createRevocationsIfNeededSQL);
		
		createStoreTable.execute();
		createRevocationTable.execute();
		
		addCertificate = conn.prepareStatement(addCertificateSQL);
		getCertByName = conn.prepareStatement(getCertNameSQL);
		getAllCerts = conn.prepareStatement(getAllCertsSQL);
		
		revokeCertificate = conn.prepareStatement(revokeCertificateSQL);
		getRevocations = conn.prepareStatement(getAllRevocationsSQL);
	}
	
	static void deleteStore() throws SQLException {
		DataSource ds = H2DataSourceFactory.getInstance().getDataSource();
		Connection conn = ds.getConnection();
		PreparedStatement deleteTable = conn.prepareStatement(deleteCertsSQL);
		final int tableNotFound = 42102;
		try {
			deleteTable.execute();
		} catch ( SQLException ex ) {
			if ( ex.getErrorCode() != tableNotFound )
				throw ex;
		}
		deleteTable = conn.prepareStatement(deleteRevocationsSQL);
		try { 
		deleteTable.execute();
		} catch ( SQLException ex ) {
			if ( ex.getErrorCode() != tableNotFound )
				throw ex;
		}
	}
	
	public static SecurityDAO getInstance() throws SQLException {
        if (instance == null) {
            synchronized(SecurityDAO.class) {
                if (instance == null)
                	instance = new SecurityDAO(); 
            }
        }
        return instance;
	}
	
	public void addCertificate(final String name, final byte[] certBytes, final byte[] certKeyBytes) throws SQLException {
		addCertificate.clearParameters();
		addCertificate.setString(1, name);
		addCertificate.setBytes(2, certBytes);
		addCertificate.setBytes(3, certKeyBytes);
		if ( certKeyBytes != null )
			addCertificate.setBytes(3, certKeyBytes);
		addCertificate.execute();
	}
	
	public CertContainer getCertByName(String name) throws SQLException, CertificateException{
		getCertByName.setString(1, name);
		ResultSet rs = getCertByName.executeQuery();
		return getCertFromResults(rs);
	}
	
	public List<CertContainer> getAllCertificates() throws SQLException, CertificateException{
		ResultSet rs = getAllCerts.executeQuery();
		return getCertsFromResults(rs);
	}
	
	static private CertContainer getCertFromResults(ResultSet rs) throws SQLException, CertificateException{
		CertContainer c = null;
		if(rs.next()){
			String name = rs.getString(CERT_NAME);
			byte[] certBytes = rs.getBytes(CERT_BYTES);
			byte[] decryptBytes = rs.getBytes(DECRYPTION_KEY);
			c = new CertContainer(name,certBytes,decryptBytes);
		}
		
		return c;
	}
	
	public List<CertContainer> getCertsFromResults(ResultSet rs) throws SQLException, CertificateException{
		List<CertContainer> containers = new ArrayList<CertContainer>();
		CertContainer c;
		while((c = getCertFromResults(rs))!=null){
			containers.add(c);
		}

		return containers;
	}	
	
	
	public void revokeCertificate(Certificate cert) throws SQLException{
		revokeCertificate.setBytes(1, cert.getCertID8());
		revokeCertificate.execute();
	}
	
	public List<byte[]> getRevokedCertificateIDs() throws SQLException{
		List<byte[]> ids = new ArrayList<byte[]>();
		
		ResultSet rs = getRevocations.executeQuery();
		while(rs.next()){
			byte[] certId = rs.getBytes(CERT_ID);
			ids.add(certId);
		}
		return ids;
	}
}
