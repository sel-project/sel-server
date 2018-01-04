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
module sel.server.java;

debug import core.thread : Thread;

import std.algorithm : canFind, all;
import std.concurrency : spawn;
import std.conv : to;
import std.datetime : dur, usecs;
import std.datetime.stopwatch : StopWatch;
import std.json : JSONValue;
import std.socket : Address, Socket, TcpSocket, UdpSocket, SocketOptionLevel, SocketOption;
import std.uuid : UUID, randomUUID;

import sel.net.modifiers : ModifierStream, LengthPrefixedStream, CompressedStream;
import sel.net.stream : Stream, TcpStream, UdpStream;
import sel.server.client : Client;
import sel.server.query : Query;
import sel.server.util;

import sul.protocol.java340.status;
import sul.protocol.java340.login;

import sul.utils.var : varuint;

debug import std.stdio : writeln;

public enum string[][uint] javaSupportedProtocols = [
	210u: ["1.10", "1.10.1", "1.10.2"],
	315u: ["1.11", "1.12"],
	316u: ["1.11.2"],
	335u: ["1.12"],
	338u: ["1.12.1"],
	340u: ["1.12.2"],
];

abstract class JavaServer : GenericGameServer {

	public shared this(shared ServerInfo info, uint[] protocols, uint[] supportedProtocols, shared Handler handler) {
		super(info, protocols, supportedProtocols, handler);
	}

	public override shared pure nothrow @property @safe @nogc ushort defaultPort() {
		return ushort(25565);
	}
	
	protected shared void onLatencyUpdated(shared JavaClient session, ulong latency) {}
	
	protected shared void onPacketReceived(shared JavaClient session, ubyte[] packet) {}

}

alias JavaServerImpl(string[][uint] supportedProtocols) = JavaServerImpl!(supportedProtocols.keys);

template JavaServerImpl(uint[] rawSupportedProtocols) if(checkProtocols(rawSupportedProtocols, javaSupportedProtocols.keys).length) {

	enum supportedProtocols = checkProtocols(rawSupportedProtocols, javaSupportedProtocols.keys);

	class JavaServerImpl : JavaServer {
	
		public shared this(shared ServerInfo info, uint[] protocols=supportedProtocols, shared Handler handler=new shared Handler()) {
			super(info, protocols, supportedProtocols, handler);
		}

		public shared this(shared ServerInfo info, shared Handler handler, uint[] protocols=supportedProtocols) {
			this(info, protocols, handler);
		}
		
		/**
		 * Starts the server in a new thread.
		 */
		protected override shared void startImpl(Address address, shared Query query) {
			Socket socket = new TcpSocket(address.addressFamily);
			socket.setOption(SocketOptionLevel.SOCKET, SocketOption.REUSEADDR, true);
			socket.blocking = true;
			socket.bind(address);
			socket.listen(10);
			spawn(&this.acceptClients, cast(shared)socket);
			if(query !is null) {
				Socket qsocket = new UdpSocket(address.addressFamily);
				qsocket.blocking = true;
				qsocket.bind(address);
				spawn(&this.acceptQueries, cast(shared)qsocket, query);
			}
		}

		/**
		 * Starts an UDP socket that is only used for the external
		 * query protocol.
		 */
		protected shared void acceptQueries(shared Socket _socket, shared Query query) {
			debug Thread.getThis().name = "java_server@" ~ (cast()_socket).localAddress.toString() ~ "/accept_queries";
			UdpStream stream = new UdpStream(cast()_socket);
			Query.Handler handler;
			with(stream.socket.localAddress) handler = (cast()query).new Handler("MINECRAFT", toAddrString(), to!ushort(toPortString()));
			Address address;
			while(true) {
				ubyte[] buffer = stream.receiveFrom(address);
				if(buffer.length >= 2 && buffer[0] == 254 && buffer[1] == 253) {
					auto data = handler.handle(buffer[2..$]);
					if(data.length) {
						debug writeln(cast(string)data);
						stream.sendTo(data, address);
					}
				}
			}
		}
		
		/**
		 * Accepts new connection and handle in a new thread.
		 */
		protected shared void acceptClients(shared Socket _socket) {
			debug Thread.getThis().name = "java_server@" ~ (cast()_socket).localAddress.toString() ~ "/accept_clients";
			Socket socket = cast()_socket;
			while(true) {
				//Socket client = socket.accept();
				spawn(&this.handleNewClient, cast(shared)socket.accept());
			}
		}
		
		protected shared void handleNewClient(shared Socket _client) {
			Socket client = cast()_client;
			debug Thread.getThis().name = "java_client@" ~ client.remoteAddress.toString() ~ "/handle";
			client.setOption(SocketOptionLevel.SOCKET, SocketOption.RCVTIMEO, dur!"seconds"(8));
			ubyte[] buffer = new ubyte[96];
			auto recv = client.receive(buffer);
			if(recv > 0) {
				// valid packet received, handle
				if(buffer[0] == 254) {
					//TODO legacy ping
				} else {
					// read as a normal minecraft packet (length, id, payload)
					immutable length = varuint.fromBuffer(buffer);
					if(length != 0 && length < recv) {
						if(varuint.fromBuffer(buffer) == Handshake.ID) {
							Handshake handshake = Handshake.fromBuffer!false(buffer);
							auto stream = new LengthPrefixedStream!varuint(new TcpStream(client), buffer.length); // first packets should be pretty small
							if(handshake.next == Handshake.LOGIN) {
								// keep this thread for the player's session
								stream.maxLength = 1024;
								this.handleNewPlayer(stream, handshake);
							} else {
								// status
								ubyte[] request = stream.receive();
								if(request.length == 1 && request[0] == Request.ID) {
									stream.send(new Response(JSONValue(this.getPingResponse(client, handshake.protocol, handshake.serverAddress, handshake.serverPort)).toString()).encode());
									// handle optional latency calculation
									// connection timeout is still set to 8 seconds
									ubyte[] latency = stream.receive();
									if(latency.length == 9 && latency[0] == Latency.ID) {
										// send back the exact same packet
										stream.send(latency);
									}
									// blocking socket should be closed only after sending everything
								}
							}
						}
					}
				}
			}
			client.close();
		}
		
		/**
		 * Gets the JSON informations that the client will use to display the server
		 * in its servers list.
		 * This method can be overridden by custom implementation of the server.
		 */
		protected shared JSONValue[string] getPingResponse(Socket client, uint protocol, string ip, ushort port) {
			if(!this.protocols.canFind(protocol)) protocol = this.protocols[$-1];
			JSONValue[string] ret;
			ret["description"] = this.info.motd.java;
			ret["version"] = ["protocol": JSONValue(protocol), "name": JSONValue(javaSupportedProtocols[protocol][0])];
			ret["players"] = ["online": JSONValue(this.info.online), "max": JSONValue(this.info.max)];
			if(this.info.favicon.length) ret["favicon"] = this.info.favicon;
			return ret;
		}
		
		/**
		 * Handles a new player connection after the handshake packet with
		 * the status set to "login".
		 * At this state the socket should be blocking with the timeout set to 8 seconds.
		 */
		protected shared void handleNewPlayer(Stream stream, Handshake handshake) {
			// receive the login packet
			ubyte[] loginp = stream.receive();
			if(varuint.fromBuffer(loginp) == LoginStart.ID) {
				LoginStart login = LoginStart.fromBuffer!false(loginp);
				// start compression
				stream.send(new SetCompression(1024).encode());
				stream = new CompressedStream!varuint(stream, 1024);
				// perform validations
				immutable disconnect = this.validatePlayer(login.username, stream.socket.remoteAddress, handshake.protocol, handshake.serverAddress, handshake.serverPort);
				if(disconnect.length) {
					stream.send(new Disconnect(JSONValue(["text": disconnect]).toString()).encode());
					//stream.socket.close();
				} else {
					// send a login success
					//TODO encryption
					UUID uuid = randomUUID();
					stream.send(new LoginSuccess(uuid.toString(), login.username).encode());
					// start real session
					shared JavaClient session = (){
						final switch(handshake.protocol) {
							foreach(protocol ; TupleOf!supportedProtocols) {
								case protocol:
									return cast(shared JavaClient)new shared JavaClientOf!protocol(stream, login.username, uuid);
							}
						}
					}();
					this.onClientJoin(session);
					session.start(this); // blocking operation, returns when the session is closed
					this.onClientLeft(session);
				}
			}
		}
		
		protected shared string validatePlayer(string username, Address address, uint protocol, string usedIp, ushort usedPort) {
			if(!this.protocols.canFind(protocol)) return protocol > this.protocols[$-1] ? "Outdated Server!" : "Outdated Client!";
			if(username.length < 3 || username.length > 16 || !username.all!(a => a >= '0' && a <= '9' || a >= 'A' && a <= 'Z' || a >= 'a' && a <= 'z' || a == '_')) return "Invalid Username";
			return "";
		}
		
	}

}

abstract class JavaClient : Client {
	
	private shared Stream stream;
	
	public shared this(uint protocol, Stream stream, string username, UUID uuid) {
		super(protocol, stream.socket.remoteAddress, username, uuid);
		this.stream = cast(shared)stream;
	}
	
	public shared void start(shared JavaServer server) {
		Stream stream = cast()this.stream;
		uint nextKeepAlive = 0;
		ubyte timeout = 0;
		StopWatch timer;
		timer.start();
		while(true) {
			ubyte[] recv = stream.receive();
			if(recv.length) {
				if(varuint.decode(recv, 0) == this.keepAliveId) {
					server.onLatencyUpdated(this, timer.peek().split!"msecs"().msecs);
				} else {
					server.onPacketReceived(this, recv);
				}
			} else if(stream.lastRecv == 0 || ++timeout == 3) {
				// connection closed by the client or timed out
				//TODO call some kind of event
				stream.socket.close();
				break;
			}
			// check whether to send keep alive
			if(timer.peek() > usecs(15_000_000)) {
				timeout = 0;
				timer.reset();
				stream.send(this.createKeepAlive(++nextKeepAlive));
			}
		}
		timer.stop();
		// thread should be stopped automatically
	}
	
	protected abstract shared @property uint keepAliveId();
	
	protected abstract shared ubyte[] createKeepAlive(uint id);
	
	/**
	 * Sends a game packet to the client.
	 */
	public override shared void send(ubyte[] packet) {
		//TODO do compression in another thread but maintain packet order
		(cast()this.stream).send(packet);
	}
	
	/**
	 * Sends a raw packet, without performing eventual compression
	 * or 0-padding.
	 */
	public override shared void directSend(ubyte[] payload) {
		(cast(ModifierStream)this.stream).stream.send(payload); // length is still appended
	}

	protected override shared void disconnectImpl(string message, bool translation) {
		Stream stream = cast()this.stream;
		stream.send(this.createDisconnect(JSONValue([(translation ? "translate" : "text"): message]).toString()));
		stream.socket.close();
		// let the client close the session when the packet has been received
	}
	
	protected abstract shared ubyte[] createDisconnect(string json);
	
}

class JavaClientOf(uint __protocol) : JavaClient {
	
	mixin("import sul.protocol.java" ~ __protocol.to!string ~ ".clientbound : ClientboundKeepAlive = KeepAlive, ClientboundDisconnect = Disconnect;");
	mixin("import sul.protocol.java" ~ __protocol.to!string ~ ".serverbound : ServerboundKeepAlive = KeepAlive;");
	
	public shared this(Stream stream, string username, UUID uuid) {
		super(__protocol, stream, username, uuid);
	}
	
	protected override shared @property uint keepAliveId() {
		return ServerboundKeepAlive.ID;
	}
	
	protected override shared ubyte[] createKeepAlive(uint id) {
		return new ClientboundKeepAlive(id).encode();
	}
	
	protected override shared ubyte[] createDisconnect(string json) {
		return new ClientboundDisconnect(json).encode();
	}
	
}

unittest {

	alias Server = JavaServerImpl!javaSupportedProtocols;

}
