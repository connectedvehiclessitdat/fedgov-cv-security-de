package gov.usdot.cv.security;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.UnknownHostException;

import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import net.sf.json.JSONSerializer;

import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;

public class SecureConfig {
	
	private static final Logger logger = Logger.getLogger(SecureConfig.class);
	
	public final Secure secure;
	
	public SecureConfig(String file) throws UnknownHostException {
		secure = new Secure(createJsonFromFile(file));
	}
	
	public SecureConfig(JSONObject config) throws UnknownHostException {
		secure = new Secure(config);
	}
	
	public static JSONObject createJsonFromFile(String file ) {
    	try {
    		FileInputStream fis = new FileInputStream(file);
    		String jsonTxt = IOUtils.toString(fis);
    		return (JSONObject) JSONSerializer.toJSON(jsonTxt);
		} catch (FileNotFoundException ex) {
			logger.error(String.format("Couldn't create JSONObject from file '%s'.\nReason: %s\n", file, ex.getMessage()));
		} catch (IOException ex) {
			logger.error(String.format("Couldn't create JSONObject from file '%s'.\nReason: %s\n", file, ex.getMessage()));
		} catch ( Exception ex) {
			logger.error(String.format("Couldn't create JSONObject from file '%s'.\nReason: %s\n", file, ex.getMessage()));
		}
    	return null;
	}
	
	public class CertEntry {
		public final String name;
		public final String path;
		public final String key;
		
		static private final String SECTION_NAME = "cert";
		
		private CertEntry(JSONObject config) {
			JSONObject cert = config.has(SECTION_NAME) ? config.getJSONObject(SECTION_NAME) : new JSONObject();
			name = cert.getString("name");
			path = cert.getString("path");
			key  = cert.optString("key", null);
		}
		
		@Override
		public String toString() {
			return String.format("\t  cert\n\t    name\t%s\n\t    path\t%s\n\t    key\t\t%s", name != null ? name : "", path != null ? path : "", key != null ? key : "");
		}
	}
	
	public class Secure {
		static private final String SECTION_NAME = "secure";
		static private final String CERTS_NAME = "certs";
		static private final boolean DEFAULT_ENABLE = false;
		static private final int DEFAULT_PSID = 0x2fe1;
		
		public final boolean enable;
		public final int psid;
		public final CertEntry[] certs;
		
		public Secure(JSONObject config) {
			JSONObject secure = config.has(SECTION_NAME) ? config.getJSONObject(SECTION_NAME) : new JSONObject();
			enable = secure.optBoolean("enable", DEFAULT_ENABLE);
			psid = secure.optInt("psid", DEFAULT_PSID);
			if ( secure.has(CERTS_NAME) ) {
				JSONArray jsonCerts = secure.getJSONArray(CERTS_NAME);
				final int count = jsonCerts.size();
				certs = new CertEntry[count];
				for( int i = 0; i < count; i++ )
					certs[i] = new CertEntry(jsonCerts.getJSONObject(i));
			} else {
				certs = null;
			}
		}
		
		@Override
		public String toString() {
			StringBuilder sb = new StringBuilder(String.format("    %s\n\tenable\t\t%s\n\tpsid\t\t0x%x\n\tcount\t\t%s\n", SECTION_NAME, enable, psid, certs != null ? certs.length : 0));
			if ( certs != null )
				for( CertEntry cert : certs)
					sb.append(cert.toString() + "\n");
			return sb.toString();
		}
	}
}
