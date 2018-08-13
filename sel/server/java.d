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
module sel.server.java;

import std.algorithm : countUntil;
import std.array : join;
import std.conv : to;
import std.datetime : seconds;
import std.datetime.stopwatch : StopWatch;
import std.json : JSONValue;
import std.socket : Address, getAddress;
import std.uuid : UUID, randomUUID;

import kiss.event : EventLoop;
import kiss.net : TcpListener, TcpStream;
import kiss.util.timer : KissTimer;

import sel.chat; //TODO
import sel.format : unformat;
import sel.protocols : javaProtocols;
import sel.server.server : GameServer, Handler;
import sel.server.util : ServerInfo, Client;
import sel.stream : Stream, LengthPrefixedModifier, CompressedModifier;

import soupply.java.protocol.login_clientbound;
import soupply.java.protocol.login_serverbound;
import soupply.java.protocol.status;

import xbuffer;

// test
import std.stdio : writeln;

class JavaServer : GameServer {

	private enum __protocols = javaProtocols.keys;

	private KissTimer timer;
	//private AsyncTCPListener[] listeners;

	private UnconnectedClient[] dead;
	private UnconnectedClient.JavaClient[uint] clients;

	public this(EventLoop eventLoop, ServerInfo serverInfo, Handler handler, uint[] protocols=__protocols) {
		super(eventLoop, serverInfo, handler, protocols);
		KissTimer timer = new KissTimer(eventLoop, 15.seconds);
		timer.onTick(&this.tick);
		timer.start();
	}

	protected override ushort defaultPort() {
		return 25565;
	}

	protected override void hostImpl(Address address) {
		TcpListener listener = new TcpListener(this.eventLoop, address.addressFamily);
		listener.bind(address);
		listener.listen(1024);
		listener.onConnectionAccepted = &this.handle;
		listener.start();
	}

	public override void kill() {

		//TODO kill timer
	}

	// handles a new connection
	private void handle(TcpListener sender, TcpStream conn) {
		UnconnectedClient client = new UnconnectedClient(conn);
		//TODO set timeout
	}

	private void tick(Object sender) {
		// send keep alive packet or disconnect them if they didn't send a keep alive response
		foreach(client ; this.clients) {
			client.tick();
		}
		//TODO delete disconnected clients
	}

	private void addJavaClient(UnconnectedClient.JavaClient client) {
		this.clients[client.id] = client;
	}

	private void removeJavaClient(UnconnectedClient.JavaClient client) {
		this.clients.remove(client.id);
	}

	private class UnconnectedClient {

		private TcpStream conn;
		
		private Buffer buffer;

		private Stream stream;

		private Handshake handshake; // used to store protocol version and ip:port used to connect

		private JavaClient client;

		public this(TcpStream conn) {
			this.conn = conn;
			this.buffer = new Buffer(1024);
			this.stream = new Stream(conn, &this.handleUnconnected);
		}
		
		private void close() {
			this.conn.close();
		}

		private void handleUnconnected(Buffer buffer) {
			if(buffer.canRead(1) && buffer.peek!ubyte() == 0xFE) with(serverInfo) {
				// legacy ping (pre-netty)
				immutable until = motd.java.countUntil('\n');
				string name = until == -1 ? motd.java : motd.java[0..until+1];
				wstring status = {
					if(buffer.canRead(2)) {
						// 1.4 to 1.6
						return join(["§1"w, "127"w, javaProtocols[protocols[$-1]][0].to!wstring, name.to!wstring, online.to!wstring, max.to!wstring], "\x00"w);
					} else {
						// beta 1.8 to 1.3
						return join([name.unformat.to!wstring, online.to!wstring, max.to!wstring], "§"w);
					}
				}();
				buffer.reset(); // recycling the buffer
				buffer.write!ubyte(0xFF);
				buffer.write!(Endian.bigEndian, ushort)(status.length & ushort.max);
				buffer.write!(Endian.bigEndian, wstring)(status);
				this.stream.send(buffer);
				this.close();
			} else {
				// add length-prefixed handler and handle again
				this.stream.handler = &this.handleHandshake;
				this.stream.modify!(LengthPrefixedModifier!varuint)();
				this.stream.buffer = buffer;
				this.stream.handleData();
			}
		}

		private void handleHandshake(Buffer buffer) {
			try if(buffer.read!varuint() == Handshake.ID) {
				this.handshake = new Handshake();
				this.handshake.decodeBody(buffer);
				if(this.handshake.next == Handshake.STATUS) {
					this.stream.handler = &this.handleRequest;
					return;
				} else if(this.handshake.next == Handshake.LOGIN) {
					this.stream.handler = &this.handleLoginStart;
					return;
				}
			} catch(BufferOverflowException) {}
			// wrong or invalid packet
			this.close();
		}

		private void handleRequest(Buffer buffer) {
			try if(buffer.read!varuint() == Request.ID) {
				buffer.reset(); // recycling the buffer one more time
				uint protocol = protocols.contains(this.handshake.protocol) ? this.handshake.protocol : protocols[$-1];
				new Response(JSONValue([
					"description": JSONValue(serverInfo.motd.java),
					"version": JSONValue(["protocol": JSONValue(protocol), "name": JSONValue(javaProtocols[protocol][0])]),
					"players": JSONValue(["online": serverInfo.online, "max": serverInfo.max]),
					"favicon": JSONValue(serverInfo.favicon)
				]).toString()).encode(buffer);
				this.stream.send(buffer);
				this.stream.handler = &this.handleLatency;
				return;
			} catch(BufferOverflowException) {}
			// wrong or invalid packet
			this.close();
		}

		private void handleLatency(Buffer buffer) {
			if(buffer.data.length == 9 && buffer.peek!ubyte() == Latency.ID) {
				// just send the exact same packet back
				this.stream.send(buffer);
			}
			// connection is always closed
			this.close();
		}

		private void handleLoginStart(Buffer buffer) {
			if(buffer.read!varuint() == LoginStart.ID) {
				LoginStart login = new LoginStart();
				login.decodeBody(buffer);
				// start compression encapsulation
				buffer.reset();
				new SetCompression(1024).encode(buffer);
				this.stream.send(buffer);
				this.stream.modify!(CompressedModifier!varuint)(1024);

				writeln(login);
				//TODO validate protocol and username

				// after validation
				this.client = new JavaClient(this.stream.conn.remoteAddress, login.username, randomUUID());
				new LoginSuccess(client.uuid.toString(), client.username).encode(buffer);
				this.stream.send(buffer);
				addJavaClient(this.client);
				handler.onJoin(this.client);
				this.stream.onClose = { removeJavaClient(client); handler.onLeft(client); };
				this.stream.handler = &client.handle;
			}
		}

		class JavaClient : Client {

			private static uint _id = 0;

			public immutable uint id;

			private ubyte serverboundKeepAliveId;
			private immutable ubyte clientboundKeepAliveId;
			private void delegate(Buffer, uint) encodeKeepAlive;

			private StopWatch stopWatch;
			private uint keepAliveCount = 1;

			this(Address address, string username, UUID uuid) {
				super(address, username, uuid);
				this.id = _id++;
				// init constants and functions
				this.serverboundKeepAliveId = getServerboundKeepAliveId(handshake.protocol);
				this.clientboundKeepAliveId = getClientboundKeepAliveId(handshake.protocol);
				this.encodeKeepAlive = getEncodeClientboundKeepAlive(handshake.protocol);
			}

			void handle(Buffer buffer) {
				if(buffer.peek!varuint() == this.serverboundKeepAliveId) {
					_latency = this.stopWatch.peek.total!"msecs".to!uint;
					handler.onLatencyUpdate(this);
				} else {
					handler.onPacket(this, buffer);
				}
			}

			void tick() {
				Buffer buffer = new Buffer(9);
				buffer.write!varuint(this.clientboundKeepAliveId);
				encodeKeepAlive(buffer, this.keepAliveCount++);
				stream.send(buffer);
				this.stopWatch.reset();
				//this.stopWatch.start();
			}

			override void disconnect(string message) {
				//TODO use sel.chat to make json
				message = `{"text":"` ~ message ~ `"}`;
				Buffer buffer = new Buffer(message.length + 5);
				encodeClientboundDisconnect(buffer, handshake.protocol, message);
				stream.send(buffer);
			}

		}

	}

}

private ubyte getServerboundKeepAliveId(uint protocol) pure nothrow @safe @nogc {
	if(protocol >= 389) return 0x0E;
	else if(protocol >= 386) return 0x0C;
	else if(protocol >= 336) return 0x0B;
	else if(protocol >= 318) return 0x0C;
	else if(protocol >= 80) return 0x0B;
	else if(protocol >= 67) return 0x0A;
	else return 0x00;
}

private ubyte getClientboundKeepAliveId(uint protocol) pure nothrow @safe @nogc {
	if(protocol >= 389) return 0x21;
	else if(protocol >= 345) return 0x20;
	else if(protocol >= 332) return 0x1F;
	else if(protocol >= 318) return 0x20;
	else if(protocol >= 86) return 0x1F;
	else if(protocol >= 80) return 0x20;
	else if(protocol >= 67) return 0x1F;
	else return 0x00;
}

private void delegate(Buffer, uint) getEncodeClientboundKeepAlive(uint protocol) pure nothrow @safe @nogc {
	if(protocol >= 339) {
		// long
		return (Buffer buffer, uint id){ buffer.write!(Endian.bigEndian, ulong)(id); };
	} else if(protocol >= 32) {
		// unsigned varint
		return (Buffer buffer, uint id){ buffer.write!varuint(id); };
	} else {
		// int
		return (Buffer buffer, uint id){ buffer.write!(Endian.bigEndian, uint)(id); };
	}
}

private void encodeClientboundDisconnect(Buffer buffer, uint protocol, string json) {
	ubyte getId() {
		if(protocol >= 345) return 0x1B;
		else if(protocol >= 332) return 0x1A;
		else if(protocol >= 318) return 0x1B;
		else if(protocol >= 80) return 0x1A;
		else return 0x19;
	}
	// id (varuint), json's length (varuint), json (bytes)
	buffer.write!ubyte(getId);
	buffer.write!varuint(json.length.to!uint);
	buffer.write(json);
}
