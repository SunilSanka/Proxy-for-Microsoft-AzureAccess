package com.broadcom.aiops;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.ProtocolException;
import java.net.URL;
import java.net.URLEncoder;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Properties;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.security.SecureRandom;

public class AzureSSLNginx {
	// URL Parameters
	private static String hostname;
	private static Integer port;
	private static String protocol;
	private static String tenenatId;
	private static String oauthUrl;
	private static String grantType;
	private static String clientId;
	private static String clientSecret;
	private static String resource;
	private static String subscriptionUrl;
	private static String subscriptionId;
	
	//HTTP Credentials
	private static String username;
	private static String password;
	
	// OAuthToken
	private static URL url;

	// KeyStore Parameters
	private static String keyStoreInstance;
	private static String keyStoreFilePath;
	private static String keyStorePassword;

	// SSL Parameters
	private static String sslProtocol;
	private static boolean isSSL = false;

	// Always Trust Manager
	private static final AlwaysTrustManager ALWAYS_TRUST_MANAGER = new AzureSSLNginx.AlwaysTrustManager();

	// Result Object
	public static HttpResult httpResult;

	public static void main(String[] args) {
		try (InputStream input = new FileInputStream("C:\\EclipseOxygen\\workspace\\probes\\APMAzureSSL\\resources\\config.properties")) {
			// Load Properties
			Properties prop = new Properties();
			prop.load(input);

			// URL Parameters
			hostname = prop.getProperty("proxy.hostname");
			protocol = prop.getProperty("proxy.protocol");
			if (protocol.equalsIgnoreCase("https"))
				isSSL = true;
		
			String portTemp = prop.getProperty("proxy.port");
			port = !portTemp.isEmpty() ? Integer.parseInt(portTemp):(isSSL==false ? 80 : 443);

			tenenatId = prop.getProperty("azure.tenentId");
			oauthUrl = prop.getProperty("url.oauth");
			subscriptionUrl = prop.getProperty("url.subscription");

			// Azure Parameters
			grantType = prop.getProperty("azure.grantType");
			clientId = prop.getProperty("azure.clientId");
			clientSecret = prop.getProperty("azure.clientSecret");
			resource = prop.getProperty("azure.resource");
			subscriptionId = prop.getProperty("azure.subscriptionId");

			//HTTP Details
			username = prop.getProperty("proxy.username");
			password = prop.getProperty("proxy.password");
			
			// KeyStore Parameters
			keyStoreInstance = prop.getProperty("keystore.instance");
			keyStoreFilePath = prop.getProperty("keystore.filepath");
			keyStorePassword = prop.getProperty("keystore.password");
			
			// Get SSL Context
			SSLContext sslContext = null;
			if (isSSL) {
				if (!keyStoreInstance.isEmpty()  &&  !keyStoreFilePath.isEmpty() &&  !keyStoreFilePath.isEmpty()) {
					sslContext = AzureSSLNginx.getKeyStoreSSLContext();
					
					// SSL Protocol
					sslProtocol = prop.getProperty("ssl.protocol");
				} else {
					sslContext = AzureSSLNginx.getAllTrustSslContext();
				}
			}
			// Get OAuth Token
			getToken(sslContext);

			// Get Azure Schema
			getSchema(sslContext);

		} catch (FileNotFoundException fne) {
			System.out.println("FileNotFoundException :" + fne);
		} catch (IOException ioe) {
			System.out.println("IOException :" + ioe);
		}

	}

	private static void getSchema(SSLContext sslContext) {
		try {
			if (null != sslContext && isSSL) {
				// Perform Handshake
				SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
				SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(hostname, port);
				sslSocket.startHandshake();
			}
			System.out.println("******************************* "+protocol+" Connection *******************************");
			// Setup Connection
			String connectionString = protocol + "://" + hostname + ":" + port + "/subscriptions/" + subscriptionId
					+ subscriptionUrl;
			url = new URL(connectionString);
			String authorizationToken = "Bearer " + httpResult.getAccessToken();

			String encoded = Base64.getEncoder().encodeToString((username+":"+password).getBytes(StandardCharsets.UTF_8));
			
			// HTTP Or HTTPS Connection
			HttpURLConnection conn = null;
			if (isSSL) {
				HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
				conn = (HttpsURLConnection) url.openConnection();

				((HttpsURLConnection) conn).setHostnameVerifier(new HostnameVerifier() {
					@Override
					public boolean verify(String hostname, SSLSession sslSession) {
						return true;
					}
				});
				
			} else {
				conn = (HttpURLConnection) url.openConnection();
			}
			conn.setDoOutput(true);
			conn.setRequestMethod("GET");
			conn.setRequestProperty("charset", "utf-8");
			conn.setRequestProperty("Content-Type", "application/json");
			conn.setRequestProperty("Authorization", authorizationToken);
			conn.setUseCaches(false);
			conn.connect();

			System.out.println("Connected :" + conn);
			System.out.println("Response Message :" + conn.getResponseMessage());
			System.out.println("Response Code :" + conn.getResponseCode());

			DataInputStream dataInputStream = new DataInputStream(conn.getInputStream());
			StringBuffer stringBuffer = new StringBuffer();
			int inputByte = dataInputStream.read();
			while (inputByte != -1) {
				stringBuffer.append((char) inputByte);
				inputByte = dataInputStream.read();
			}
			String result = stringBuffer.toString();
			System.out.println("Reslut :" + result);
			conn.disconnect();
			System.out.println("******************************* Done with Schema *******************************");

		} catch (Exception e) {
			System.out.println("Exception in getSchema:" + e.getMessage());
		}
	}

	private static void getToken(SSLContext sslContext) {
		try {
			if (null != sslContext && isSSL) {
				// Perform Handshake
				SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
				SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(hostname, port);
				sslSocket.startHandshake();
			}

			System.out.println("****************************** "+protocol.toUpperCase()+" Connection *******************************");
			// Setup Connection
			String connectionString = protocol + "://" + hostname + ":" + port + "/" + tenenatId + oauthUrl;
			System.out.println("Connection String :" + connectionString);
			url = new URL(connectionString);

			String data = URLEncoder.encode("grant_type", "UTF-8") + "=" + URLEncoder.encode(grantType, "UTF-8");
			data += "&" + URLEncoder.encode("client_id", "UTF-8") + "=" + URLEncoder.encode(clientId, "UTF-8");
			data += "&" + URLEncoder.encode("client_secret", "UTF-8") + "=" + URLEncoder.encode(clientSecret, "UTF-8");
			data += "&" + URLEncoder.encode("resource", "UTF-8") + "=" + URLEncoder.encode(resource, "UTF-8");

			String encoded = Base64.getEncoder().encodeToString((username+":"+password).getBytes(StandardCharsets.UTF_8));
			
			
			// HTTP Or HTTPS Connection parameters
			HttpURLConnection conn = null;
			if (isSSL) {
				HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
				conn = (HttpsURLConnection) url.openConnection();
				((HttpsURLConnection) conn).setHostnameVerifier(new HostnameVerifier() {
					@Override
					public boolean verify(String hostname, SSLSession sslSession) {
						return true;
					}
				});

			} else {
				conn = (HttpURLConnection) url.openConnection();
				conn.setRequestProperty("Authorization", "Basic "+encoded);
			}
			conn.setDoOutput(true);
			conn.setRequestMethod("POST");
			conn.setRequestProperty("charset", "utf-8");
			conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
			conn.setUseCaches(false);
			conn.connect();

			try (OutputStreamWriter wr = new OutputStreamWriter(conn.getOutputStream())) {
				wr.write(data);
				wr.flush();
			}

			System.out.println("Connected :" + conn);
			System.out.println("Response Message :" + conn.getResponseMessage());
			System.out.println("Response Code :" + conn.getResponseCode());

			DataInputStream dataInputStream = new DataInputStream(conn.getInputStream());
			StringBuffer stringBuffer = new StringBuffer();
			int inputByte = dataInputStream.read();
			while (inputByte != -1) {
				stringBuffer.append((char) inputByte);
				inputByte = dataInputStream.read();
			}
			String result = stringBuffer.toString();
			System.out.println("Reslut :" + result);
			conn.disconnect();
			prepareResponseObject(result);
			System.out.println("******************************* Done with Token *******************************");
		} catch (ProtocolException pe) {
			System.out.println("ProtocolException Occured :" + pe.getMessage());
		} catch (UnknownHostException uhe) {
			System.out.println("UnknownHostException Occured :" + uhe.getMessage());
		} catch (IOException ioe) {
			System.out.println("IOException Occured :" + ioe.getMessage());
		}
	}

	// Prepare the HTTPResult object
	private static void prepareResponseObject(String loginResult) {
		try {
			httpResult = new HttpResult();
			JSONParser parser = new JSONParser();
			JSONObject obj = (JSONObject) parser.parse(loginResult);

			// Populate the results
			httpResult.setTokenType((String) obj.get("token_type"));
			httpResult.setExpiresIn((String) obj.get("expires_in"));
			httpResult.setExtExpiresIn((String) obj.get("ext_expires_in"));
			httpResult.setExpiresOn((String) obj.get("expires_on"));
			httpResult.setNotBefore((String) obj.get("not_before"));
			httpResult.setResource((String) obj.get("resource"));
			httpResult.setAccessToken((String) obj.get("access_token"));

		} catch (ParseException pe) {
			System.out.println("ParseException :" + pe.getMessage());
		}
	}

	private static SSLContext getKeyStoreSSLContext() {
		try {
			System.out.println("Into getKeyStoreSSLContext");
			KeyStore keyStore = KeyStore.getInstance(keyStoreInstance);
			File keyStoreFile = new File(keyStoreFilePath);
			FileInputStream fis = new FileInputStream(keyStoreFile);
			keyStore.load(fis, keyStorePassword.toCharArray());
			fis.close();

			// Create key manager
			KeyManagerFactory keyManagerFactory = KeyManagerFactory
					.getInstance(KeyManagerFactory.getDefaultAlgorithm());
			keyManagerFactory.init(keyStore, keyStorePassword.toCharArray());
			KeyManager[] km = keyManagerFactory.getKeyManagers();

			// Create trust manager
			TrustManagerFactory trustManagerFactory = TrustManagerFactory
					.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			trustManagerFactory.init(keyStore);
			TrustManager[] tm = trustManagerFactory.getTrustManagers();

			// Initialize SSLContext
			SSLContext sslContext = SSLContext.getInstance(sslProtocol);
			sslContext.init(km, tm, null);
			return sslContext;
		} catch (Exception ex) {
			ex.printStackTrace();
			return null;
		}
	}

	// SSLContext - Taken from RESTmon code base
	public static SSLContext getAllTrustSslContext() {
		System.out.println("Into getAllTrustContext");
		synchronized (ALWAYS_TRUST_MANAGER) {
			SSLContext sslContext = null;
			try {
				// Initialize SSLContext
				sslContext = SSLContext.getInstance("SSL");
				sslContext.init(null, new TrustManager[] { ALWAYS_TRUST_MANAGER }, new SecureRandom());
			} catch (NoSuchAlgorithmException e) {
				System.out.println();

			} catch (KeyManagementException e) {
				System.out.println();
			}
			return sslContext;
		}
	}

	// AlwaysTrustManager - Taken from RESTmon code base
	private static class AlwaysTrustManager implements X509TrustManager {
		public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
			// no check done, always trusted
		}

		public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
			// no check done, always trusted
		}

		public X509Certificate[] getAcceptedIssuers() {
			return null;
		}
	}
}
