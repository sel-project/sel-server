/*
 * Copyright (c) 2017-2018 SEL
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Lesser General Public License for more details.
 * 
 */
module sel.server.server;

import core.atomic : atomicOp;

import std.algorithm : sort, all, canFind;
import std.conv : to;
import std.socket : Address, getAddress;
import std.typetuple : TypeTuple;

import sel.server.client : Client;
import sel.server.query : Query;

/**
 * Basic server's informations, used to display the server in the
 * game's server list and in the queries.
 */
class ServerInfo {

	static struct MOTD {

		string raw;

		string bedrock, java;

		this(string motd) {
			this.opAssign(motd);
		}

		void opAssign(string motd) {
			this.raw = motd; //TODO remove formatting
			this.bedrock = this.java = motd;
		}

		shared void opAssign(string motd) {
			(cast()this).opAssign(motd);
		}

	}
	
	public MOTD motd = MOTD("A Minecraft Server");
	
	public int online = 0;
	public int max = 32;

	public string favicon; // must be already encoded

	public string gametype = "SMP";
	public string map = "world";
	
}

abstract class GenericServer {

	protected shared ServerInfo info;

	public shared this(shared ServerInfo info) {
		this.info = info;
	}
	
	/**
	 * Starts the server on the given address.
	 * The server can be started using an ip/port combination (if the port
	 * is not given the game's default one will be used), and an optional
	 * handler (for the management of the players) and a query.
	 */
	public final shared void start(Address address, shared Query query=null) {
		this.startImpl(address, query);
	}
	
	/// ditto
	public final shared void start(string ip, ushort port, shared Query query=null) {
		this.start(getAddress(ip, port)[0], query);
	}
	
	/// ditto
	public final shared void start(string ip, shared Query query=null) {
		this.start(ip, this.defaultPort, query);
	}
	
	protected abstract shared void startImpl(Address address, shared Query query);
	
	/**
	 * Gets the server's default port for the hosted game.
	 */
	public abstract shared pure nothrow @property @safe @nogc ushort defaultPort();

}

/**
 * A generic server that only contains a ServerInfo, the supported protocols
 * and the mothods to start it.
 */
abstract class GenericGameServer : GenericServer {

	private immutable immutable(uint)[] supported;
	protected immutable(uint)[] _protocols;
	protected shared Handler handler;
	
	public shared this(shared ServerInfo info, uint[] protocols, uint[] supported, shared Handler handler) {
		super(info);
		this.supported = supported.idup;
		this.protocols = protocols;
		this.handler = handler;
	}

	public final shared pure nothrow @property @safe @nogc immutable(uint)[] protocols() {
		return this._protocols;
	}

	public final shared @property immutable(uint)[] protocols(uint[] protocols) {
		return this._protocols = checkProtocols(protocols, this.supported).idup;
	}

	protected shared void onClientJoin(shared Client client) {
		atomicOp!"+="(this.info.online, 1);
		this.handler.onClientJoin(client);
	}

	protected shared void onClientLeft(shared Client client) {
		atomicOp!"-="(this.info.online, 1);
		this.handler.onClientLeft(client);
	}

}

class Handler {

	public shared void onClientJoin(shared Client client) {}

	public shared void onClientLeft(shared Client client) {}

	public shared void onClientPacket(shared Client client, ubyte[] packet) {}

}

uint[] checkProtocols(uint[] protocols, inout(uint)[] supported) {
	sort(protocols);
	uint[] ret;
	foreach(i, protocol; protocols) {
		if(supported.canFind(protocol) && (ret.length == 0 || protocol != ret[$-1])) {
			ret ~= protocol;
		}
	}
	return ret;
}

template TupleOf(alias array) {
	mixin((){
		string ret = "alias TupleOf = TypeTuple!(";
		foreach(element ; array) {
			ret ~= element.to!string;
			ret ~= ",";
		}
		return ret ~ ");";
	}());
}
