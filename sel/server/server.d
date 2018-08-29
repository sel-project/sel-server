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
module sel.server.server;

import std.algorithm : sort;
import std.range : SortedRange;
import std.socket : Address, getAddress;

import kiss.event : EventLoop;

import sel.server.util : ServerInfo, Client;

import xbuffer : Buffer;

/**
 * Base class for every server. It contains an event loop and
 * informations about the server.
 */
class Server {

	private EventLoop _eventLoop;
	private ServerInfo _serverInfo;

	public this(EventLoop eventLoop, ServerInfo serverInfo) {
		_eventLoop = eventLoop;
		_serverInfo = serverInfo;
	}

	/**
	 * Gets the server's event loop.
	 */
	public @property EventLoop eventLoop() pure nothrow @safe @nogc {
		return _eventLoop;
	}

	/**
	 * Gets the server's game informations.
	 */
	public @property ServerInfo serverInfo() pure nothrow @safe @nogc {
		return _serverInfo;
	}

	/**
	 * Gets the server's default port.
	 */
	protected abstract @property ushort defaultPort() pure nothrow @safe @nogc;

	/**
	 * Starts the server on the given address or ip/port combination.
	 */
	public void host(Address address) {
		this.hostImpl(address);
	}

	/// ditto
	public void host(string ip, ushort port) {
		this.host(getAddress(ip, port)[0]);
	}

	/// ditto
	public void host(string ip) {
		this.host(ip, this.defaultPort);
	}

	protected abstract void hostImpl(Address address);

	/**
	 * Stops every listener started with the `host` method.
	 */
	public abstract void stop();

}

/**
 * Base class for every game server.
 */
class GameServer : Server {

	alias SortedProtocols = SortedRange!(uint[], "a < b");

	protected Handler handler;

	private SortedProtocols _protocols;

	this(EventLoop eventLoop, ServerInfo serverInfo, Handler handler, uint[] protocols) {
		super(eventLoop, serverInfo);
		this.handler = handler;
		_protocols = sort(protocols); //TODO remove duplicates and verify that they're accepted
	}

	/**
	 * Gets the sorted protocols accepted by the server.
	 * Example:
	 * ---
	 * assert(server.protocols.contains(120));
	 * ---
	 */
	public @property SortedProtocols protocols() pure nothrow @safe @nogc {
		return _protocols;
	}

}


interface Handler {

	void onJoin(Client);

	void onLeft(Client);

	void onPacket(Client, Buffer);

	void onLatencyUpdate(Client);

	void onPacketLossUpdate(Client);

}

class DefaultHandler : Handler {

	override void onJoin(Client client) {}

	override void onLeft(Client client) {}

	override void onPacket(Client client, Buffer buffer) {}

	override void onLatencyUpdate(Client client) {}

	override void onPacketLossUpdate(Client client) {}

}
