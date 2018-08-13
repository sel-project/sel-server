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

import std.uuid : UUID;

import sel.format : unformat;

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

class Client {

	private string _username;
	private UUID _uuid;

	protected uint _latency = 0;
	protected float _packetLoss = 0;

	this(string username, UUID uuid) {
		_username = username;
		_uuid = uuid;
	}

	public @property string username() pure nothrow @safe @nogc {
		return _username;
	}

	public @property UUID uuid() pure nothrow @safe @nogc {
		return _uuid;
	}

	public @property uint latency() pure nothrow @safe @nogc {
		return _latency;
	}

	public @property float packetLoss() pure nothrow @safe @nogc {
		return _packetLoss;
	}

	public abstract void disconnect(string message);

}
