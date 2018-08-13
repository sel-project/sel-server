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
module sel.server.query;

import std.conv : to;
import std.system : endian;

import kiss.event : EventLoop;

import sel.server.server : Server;
import sel.server.util;

import xbuffer;

version(Query):

// test
import std.stdio : writeln;

class QueryServer : Server {

	private QueryInfo _queryInfo;

	private string game;

	this(EventLoop eventLoop, QueryInfo queryInfo, string game) {
		super(eventLoop, queryInfo.serverInfo);
		_queryInfo = queryInfo;
		this.game = game;
	}

	public @property QueryInfo queryInfo() pure nothrow @safe @nogc {
		return _queryInfo;
	}

	protected override bool hostImpl(string ip, ushort port) {
		//TODO create UDP socket and receive
		AsyncUDPSocket socket = new AsyncUDPSocket(this.eventLoop);
		socket.host(ip, port);
		auto handler = new QueryHandler(ip, port);
		return handler.run();
	}

	public override void kill() {
		//TODO
	}

	private class QueryHandler {

		private string ip;
		private ushort port;

		this(string ip, ushort port) {
			this.ip = ip;
			this.port = port;
		}

		bool run() {
			AsyncUDPSocket socket = new AsyncUDPSocket(eventLoop);
			socket.host(this.ip, this.port);
			return socket.run(&this.handle);
		}

		void handle(UDPEvent event) {
			writeln(event);
		}

		private void writeShortQuery(Buffer buffer) {
			void put(Endian endianness=endian, T)(T value) {
				buffer.write!endianness(value);
				buffer.write!ubyte(0);
			}
			put(serverInfo.motd.raw);
			put(queryInfo.gametype);
			put(queryInfo.map);
			put(to!string(serverInfo.online));
			put(to!string(serverInfo.max));
			put!(Endian.littleEndian, ushort)(this.port);
			put(this.ip);
		}

		private void writeLongQuery(Buffer buffer) {
			//TODO
		}

	}

}

class BedrockQueryServer : QueryServer {

	public this(EventLoop eventLoop, QueryInfo queryInfo) {
		super(eventLoop, queryInfo, "MINECRAFTPE");
	}

	public this(QueryInfo queryInfo) {
		this(getThreadEventLoop(), queryInfo);
	}

	public this(EventLoop eventLoop, ServerInfo serverInfo) {
		this(eventLoop, new QueryInfo(serverInfo));
	}

	public this(ServerInfo serverInfo) {
		this(getThreadEventLoop, serverInfo);
	}

	protected override ushort defaultPort() {
		return 19132;
	}

}

class JavaQueryServer : QueryServer {

	public this(EventLoop eventLoop, QueryInfo queryInfo) {
		super(eventLoop, queryInfo, "MINECRAFT");
	}
	
	public this(QueryInfo queryInfo) {
		this(getThreadEventLoop(), queryInfo);
	}
	
	public this(EventLoop eventLoop, ServerInfo serverInfo) {
		this(eventLoop, new QueryInfo(serverInfo));
	}
	
	public this(ServerInfo serverInfo) {
		this(getThreadEventLoop, serverInfo);
	}

	protected override ushort defaultPort() {
		return 25565;
	}

}
