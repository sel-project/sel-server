/*
 * Copyright (c) 2017 SEL
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
module sel.server.util;

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
	
	public string motd = "A Minecraft Server";
	
	public int online = 0;
	public int max = 32;

	public string favicon; // must be already encoded

	public string gametype = "SMP";
	public string map = "world";
	
}

/**
 * A generic server that only contains a ServerInfo, the supported protocols
 * and the mothods to start it.
 */
abstract class GenericServer {

	protected shared ServerInfo info;
	public immutable immutable(uint)[] protocols;
	
	public shared this(shared ServerInfo info, uint[] protocols, uint[] supported) {
		this.info = info;
		this.protocols = checkProtocols(protocols, supported).idup;
		assert(this.protocols.length);
	}

	/**
	 * Starts the server.
	 * The server can be started using an ip/port combination (if the port
	 * is not given the game's default one will be used), and an optional
	 * handler (for the management of the players) and a query.
	 */
	public final shared void start(Address address, shared Handler handler=new shared Handler(), shared Query query=null) {
		return this.startImpl(address, handler, query);
	}

	/// ditto
	public final shared void start(Address address, shared Query query) {
		return this.start(address, new shared Handler(), query);
	}

	/// ditto
	public final shared void start(string ip, ushort port, shared Handler handler=new shared Handler(), shared Query query=null) {
		return this.start(getAddress(ip, port)[0], handler, query);
	}

	/// ditto
	public final shared void start(string ip, ushort port, shared Query query) {
		return this.start(ip, port, new shared Handler(), query);
	}

	/// ditto
	public final shared void start(string ip, shared Handler handler=new shared Handler(), shared Query query=null) {
		return this.start(ip, this.defaultPort, handler, query);
	}

	/// ditto
	public final shared void start(string ip, shared Query query) {
		return this.start(ip, new shared Handler(), query);
	}

	protected abstract shared void startImpl(Address address, shared Handler handler, shared Query query);

	/**
	 * Gets the server's default port for the hosted game.
	 */
	public abstract shared pure nothrow @property @safe @nogc ushort defaultPort();

}

class Handler {

	public shared void onClientJoin(shared Client client) {}

	public shared void onClientLeft(shared Client client) {}

}

uint[] checkProtocols(uint[] protocols, uint[] supported) {
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
