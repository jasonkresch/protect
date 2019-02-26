package com.ibm.pross.server.app.http;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.Executors;

import com.ibm.pross.server.app.http.handlers.BaseHandler;
import com.ibm.pross.server.app.http.handlers.InfoHandler;
import com.sun.net.httpserver.HttpServer;

import bftsmart.reconfiguration.util.sharedconfig.ServerConfiguration;

@SuppressWarnings("restriction")
public class HttpRequestProcessor {

	public static final int BASE_HTTP_PORT = 8080;

	public static int SHUTDOWN_DELAY_SECONDS = 5;
	public static int NUM_PROCESSING_THREADS = 15;

	private final HttpServer server;

	public HttpRequestProcessor(final int serverIndex, final ServerConfiguration serverConfig) throws IOException {

		final int httpListenPort = BASE_HTTP_PORT + serverIndex;

		this.server = HttpServer.create(new InetSocketAddress(httpListenPort), 0);
		System.out.println("HTTP server listening on port: " + httpListenPort);

		// Returns basic information about this server:
		// quorum information, other servers)
		this.server.createContext("/", new BaseHandler(serverIndex, serverConfig));

		// Define request handlers for the supported client operations
		this.server.createContext("/generate", new InfoHandler());
		this.server.createContext("/read", new InfoHandler());
		this.server.createContext("/store", new InfoHandler());
		this.server.createContext("/info", new InfoHandler());
		this.server.createContext("/delete", new InfoHandler());
		this.server.createContext("/disable", new InfoHandler());
		this.server.createContext("/enable", new InfoHandler());
		this.server.createContext("/exponentiate", new InfoHandler());
		this.server.createContext("/rsa_sign", new InfoHandler());

		// Define server to server requests
		this.server.createContext("/recover", new InfoHandler());

		// this.server.setExecutor(Executors.newFixedThreadPool(NUM_PROCESSING_THREADS));
	}

	public void start() {
		this.server.start();
	}

	public void stop() {
		this.server.stop(SHUTDOWN_DELAY_SECONDS);
	}

}
