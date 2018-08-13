/*
 * Copyright (c) 2017-2018 sel-project
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */
module sel.server.util;

import std.socket : Address;
import std.uuid : UUID;

import sel.format : unformat;

/**
 * Informations about a server.
 */
class ServerInfo {
	
	static struct MOTD {
		
		string raw;
		
		string bedrock, java;
		
		this(string motd) {
			this.opAssign(motd);
		}
		
		void opAssign(string motd) {
			this.raw = motd.unformat;
			this.bedrock = this.java = motd;
		}
		
	}
	
	public MOTD motd = MOTD("A Minecraft Server");
	
	public int online = 0;
	public int max = 32;
	
	public string favicon; // must be already encoded
	
}

/**
 * Informations about a query.
 */
class QueryInfo {

	ServerInfo serverInfo;

	string software = "sel-server";
	string[] plugins;
	
	string gametype = "SMP";
	string map = "world";

	this(ServerInfo serverInfo) {
		this.serverInfo = serverInfo;
	}

	alias serverInfo this;

}

/**
 * Representation of a client. Java and Bedrock clients extend
 * this class.
 */
class Client {

	private Address _address;

	private string _username;
	private UUID _uuid;

	protected uint _latency = 0;
	protected float _packetLoss = 0;

	this(Address address, string username, UUID uuid) {
		_address = address;
		_username = username;
		_uuid = uuid;
	}

	/**
	 * Gets the client's address.
	 */
	public @property Address address() pure nothrow @safe @nogc {
		return _address;
	}

	/**
	 * Gets the client's username.
	 */
	public @property string username() pure nothrow @safe @nogc {
		return _username;
	}

	/**
	 * Gets the client's UUID.
	 */
	public @property UUID uuid() pure nothrow @safe @nogc {
		return _uuid;
	}

	/**
	 * Gets the client's latency. For Java it is calculated
	 * using the KeepAlive packets and it is very precise thanks
	 * to the TCP protocol used; for Bedrock it is calculated using
	 * the connected ping and pong packets and may be not very precise
	 * due to the usage of an UDP protocol.
	 */
	public @property uint latency() pure nothrow @safe @nogc {
		return _latency;
	}

	/**
	 * Gets the client's packet loss, which is a number between 0
	 * (no packet is lost) and 100 (every packet is lost).
	 * Only for Bedrock.
	 */
	public @property float packetLoss() pure nothrow @safe @nogc {
		return _packetLoss;
	}

	/**
	 * Disconnects the client with the given message.
	 */
	public abstract void disconnect(string message);

}
