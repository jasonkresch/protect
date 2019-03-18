/**
Copyright (c) 2007-2013 Alysson Bessani, Eduardo Alchieri, Paulo Sousa, and the authors indicated in the @author tags

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package bftsmart.reconfiguration.util;

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.Map;

import com.ibm.pross.common.config.ServerConfiguration;
import com.ibm.pross.common.config.ServerConfigurationLoader;


public class HostsConfig {

	private Map<Integer, Config> servers = new HashMap<Integer, Config>();

	private ServerConfiguration serverConfig;
	
	/** Creates a new instance of ServersConfig 
	 * @param hostsFileName */
	public HostsConfig(String configHome, String hostsFileName) {
		loadConfig(configHome, hostsFileName);
	}

	private void loadConfig(String configHome, String hostsFileName) {

		try {
			if (configHome == "")
			{
				configHome = (new File("config")).getAbsolutePath();
			}
			
			File serverFile = new File(new File(configHome), "server");
			File hostFile = new File(serverFile, hostsFileName);
			this.serverConfig = ServerConfigurationLoader.load(hostFile);

			int id = 0;
			for (InetSocketAddress server : serverConfig.getServerAddresses()) {
				add(id++, server.getHostString(), server.getPort()+200);
			}
		} catch (IOException e) {
			e.printStackTrace(System.out);
		}
	}

	public void add(int id, String host, int port) {
		if (this.servers.get(id) == null) {
			this.servers.put(id, new Config(id, host, port));
		}
	}

	public int getNum() {
		return servers.size();
	}

	public InetSocketAddress getRemoteAddress(int id) {
		Config c = (Config) this.servers.get(id);
		if (c != null) {
			return new InetSocketAddress(c.host, c.port);
		}
		return null;
	}

	public InetSocketAddress getServerToServerRemoteAddress(int id) {
		Config c = (Config) this.servers.get(id);
		if (c != null) {
			return new InetSocketAddress(c.host, c.port + 1);
		}
		return null;
	}

	public int getPort(int id) {
		Config c = (Config) this.servers.get(id);
		if (c != null) {
			return c.port;
		}
		return -1;
	}

	public int getServerToServerPort(int id) {
		Config c = (Config) this.servers.get(id);
		if (c != null) {
			return c.port + 1;
		}
		return -1;
	}

	public String getHost(int id) {
		Config c = (Config) this.servers.get(id);
		if (c != null) {
			return c.host;
		}
		return null;
	}

	public InetSocketAddress getLocalAddress(int id) {
		Config c = (Config) this.servers.get(id);
		if (c != null) {
			return new InetSocketAddress(c.port);
		}
		return null;
	}
	
	public ServerConfiguration getServerConfiguration()
	{
		return this.serverConfig;
	}

	public class Config {
		public final int id;
		public final String host;
		public final int port;

		public Config(int id, String host, int port) {
			this.id = id;
			this.host = host;
			this.port = port;
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + getEnclosingInstance().hashCode();
			result = prime * result + ((host == null) ? 0 : host.hashCode());
			result = prime * result + id;
			result = prime * result + port;
			return result;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;
			if (obj == null)
				return false;
			if (getClass() != obj.getClass())
				return false;
			Config other = (Config) obj;
			if (!getEnclosingInstance().equals(other.getEnclosingInstance()))
				return false;
			if (host == null) {
				if (other.host != null)
					return false;
			} else if (!host.equals(other.host))
				return false;
			if (id != other.id)
				return false;
			if (port != other.port)
				return false;
			return true;
		}

		private HostsConfig getEnclosingInstance() {
			return HostsConfig.this;
		}
		
		
	}
}
