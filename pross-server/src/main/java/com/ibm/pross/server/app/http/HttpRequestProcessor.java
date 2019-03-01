package com.ibm.pross.server.app.http;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentMap;

import com.ibm.pross.server.app.avpss.ApvssShareholder;
import com.ibm.pross.server.app.http.handlers.ExponentiateHandler;
import com.ibm.pross.server.app.http.handlers.GenerateHandler;
import com.ibm.pross.server.app.http.handlers.InfoHandler;
import com.ibm.pross.server.app.http.handlers.ReadHandler;
import com.ibm.pross.server.app.http.handlers.RootHandler;
import com.ibm.pross.server.configuration.permissions.AccessEnforcement;
import com.sun.net.httpserver.HttpServer;

import bftsmart.reconfiguration.util.sharedconfig.ServerConfiguration;

@SuppressWarnings("restriction")
public class HttpRequestProcessor {

	public static final int BASE_HTTP_PORT = 8080;

	public static int SHUTDOWN_DELAY_SECONDS = 5;
	public static int NUM_PROCESSING_THREADS = 15;

	private final HttpServer server;

	public HttpRequestProcessor(final int serverIndex, final ServerConfiguration serverConfig,
			final AccessEnforcement accessEnforcement, final ConcurrentMap<String, ApvssShareholder> shareholders)
			throws IOException {

		final int httpListenPort = BASE_HTTP_PORT + serverIndex;

		this.server = HttpServer.create(new InetSocketAddress(httpListenPort), 0);
		System.out.println("HTTP server listening on port: " + httpListenPort);

		// Returns basic information about this server:
		// quorum information, other servers)
		this.server.createContext("/", new RootHandler(serverIndex, serverConfig, shareholders));

		// Define request handlers for the supported client operations
		this.server.createContext("/generate", new GenerateHandler(accessEnforcement, shareholders));
		this.server.createContext("/info", new InfoHandler(accessEnforcement, serverConfig, shareholders));

		// Handlers for reading or storing shares
		this.server.createContext("/read", new ReadHandler(accessEnforcement, serverConfig, shareholders));
		this.server.createContext("/store", new InfoHandler(accessEnforcement, serverConfig, shareholders));
		// implement as DKG with default value given to each shareholder (must use
		// interpolation style DKG!)

		// Handlers for deleting or recovering shares
		this.server.createContext("/delete", new InfoHandler(accessEnforcement, serverConfig, shareholders));
		this.server.createContext("/recover", new InfoHandler(accessEnforcement, serverConfig, shareholders));

		// Handlers for enabling and disabling shares
		this.server.createContext("/enable", new InfoHandler(accessEnforcement, serverConfig, shareholders));
		this.server.createContext("/disable", new InfoHandler(accessEnforcement, serverConfig, shareholders));

		// Handlers for using the shares to perform functions
		this.server.createContext("/exponentiate", new ExponentiateHandler(accessEnforcement, shareholders));
		this.server.createContext("/rsa_sign", new InfoHandler(accessEnforcement, serverConfig, shareholders));

		// Define server to server requests
		this.server.createContext("/get_partial", new InfoHandler(accessEnforcement, serverConfig, shareholders));

		// this.server.setExecutor(Executors.newFixedThreadPool(NUM_PROCESSING_THREADS));
	}

	public void start() {
		this.server.start();
	}

	public void stop() {
		this.server.stop(SHUTDOWN_DELAY_SECONDS);
	}

	/**
	 * From:
	 * https://stackoverflow.com/questions/13592236/parse-a-uri-string-into-name-value-collection
	 * 
	 * @param url
	 * @return
	 * @throws UnsupportedEncodingException
	 */
	public static Map<String, List<String>> parseQueryString(final String queryString)
			throws UnsupportedEncodingException {

		final Map<String, List<String>> queryPairs = new LinkedHashMap<String, List<String>>();
		final String[] pairs = queryString.split("&");
		for (String pair : pairs) {
			final int idx = pair.indexOf("=");
			final String key = idx > 0 ? URLDecoder.decode(pair.substring(0, idx), "UTF-8") : pair;
			if (!queryPairs.containsKey(key)) {
				queryPairs.put(key, new LinkedList<String>());
			}
			final String value = idx > 0 && pair.length() > idx + 1
					? URLDecoder.decode(pair.substring(idx + 1), "UTF-8")
					: null;
			queryPairs.get(key).add(value);
		}
		return queryPairs;
	}

}
