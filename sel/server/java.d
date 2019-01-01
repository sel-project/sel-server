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
/**
 * Copyright: 2017-2019 sel-project
 * License: LGPL-3.0
 * Authors: Kripth
 * Source: $(HTTP github.com/sel-project/sel-server/sel/server/java.d, sel/server/java.d)
 */
module sel.server.java;

debug import core.thread : Thread;

import std.algorithm : canFind, all;
import std.bitmanip : nativeToBigEndian;
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
import sel.server.server;

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

class JavaServer : GenericGameServer {
	
	public shared this(shared ServerInfo info, uint[] protocols=supportedProtocols.keys, shared Handler handler=new shared Handler()) {
		super(info, protocols, supportedProtocols.keys, handler);
	}

	public shared this(shared ServerInfo info, shared Handler handler) {
		this(info, supportedProtocols.keys, handler);
	}
	
	public override shared pure nothrow @property @safe @nogc ushort defaultPort() {
		return ushort(25565);
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
	 * This method can be overridden by custom implementations of the server.
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
				shared JavaClient session = new shared JavaClient(handshake.protocol, stream, login.username, uuid);
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

class JavaClient : Client {
	
	private shared Stream stream;

	private immutable ubyte serverboundKeepAliveId;
	private immutable ubyte clientboundKeepAliveId;
	private ubyte[] delegate(uint) encodeKeepAlive;
	
	public shared this(uint protocol, Stream stream, string username, UUID uuid) {
		super(JAVA, protocol, stream.socket.remoteAddress, username, uuid, VERSION_JAVA, javaSupportedProtocols[protocol][0]);
		this.stream = cast(shared)stream;
		this.serverboundKeepAliveId = getServerboundKeepAliveId(protocol);
		this.clientboundKeepAliveId = getClientboundKeepAliveId(protocol);
		this.encodeKeepAlive = getEncodeClientboundKeepAlive(protocol);
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
				if(varuint.decode(recv, 0) == this.serverboundKeepAliveId) {
					//server.onLatencyUpdated(this, timer.peek().split!"msecs"().msecs); //TODO call on handler
				} else {
					// should never be compressed
					server.handler.onClientPacket(this, recv);
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
				stream.send(this.clientboundKeepAliveId ~ this.encodeKeepAlive(++nextKeepAlive));
			}
		}
		timer.stop();
		// thread should be stopped automatically
	}
	
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

	protected override shared void disconnectImpl(string message, bool translation, string[] params) {
		JSONValue[string] reason;
		reason[translation ? "translate" : "text"] = message;
		if(params.length) {
			JSONValue[] rp;
			foreach(param ; params) rp ~= JSONValue(["text": param]);
			reason["with"] = rp;
		}
		Stream stream = cast()this.stream;
		stream.send(encodeClientboundDisconnect(this.protocol, JSONValue(reason).toString()));
		stream.socket.close();
		// let the client close the session when the packet has been received
	}
	
}

private ubyte getServerboundKeepAliveId(uint protocol) {
	if(protocol >= 336) return 0x0B;
	else if(protocol >= 318) return 0x0C;
	else if(protocol >= 80) return 0x0B;
	else if(protocol >= 67) return 0x0A;
	else return 0x00;
}

private ubyte getClientboundKeepAliveId(uint protocol) {
	if(protocol >= 332) return 0x1F;
	else if(protocol >= 318) return 0x20;
	else if(protocol >= 86) return 0x1F;
	else if(protocol >= 80) return 0x20;
	else if(protocol >= 67) return 0x1F;
	else return 0x00;
}

private ubyte[] delegate(uint) getEncodeClientboundKeepAlive(uint protocol) {
	if(protocol >= 339) {
		// long
		return delegate ubyte[] (uint id){ return nativeToBigEndian!ulong(id).dup; };
	} else if(protocol >= 32) {
		// unsigned varint
		return delegate ubyte[] (uint id){ return varuint.encode(id); };
	} else {
		// int
		return delegate ubyte[] (uint id){ return nativeToBigEndian!uint(id).dup; };
	}
}

private ubyte[] encodeClientboundDisconnect(uint protocol, string json) {
	ubyte getId() {
		if(protocol >= 332) return 0x1A;
		else if(protocol >= 318) return 0x1B;
		else if(protocol >= 80) return 0x1A;
		else return 0x19;
	}
	// id (varuint), json's length (varuint), json (bytes)
	return getId() ~ varuint.encode(json.length.to!uint) ~ cast(ubyte[])json;
}

enum string[][uint] supportedProtocols = [
	4: ["1.7.1-pre", "1.7.2", "1.7.3-pre", "1.7.4", "1.7.5"],
	5: ["1.7.6", "1.7.7", "1.7.8", "1.7.9", "1.7.10", "14w02a"],
	6: ["14w03a"],
	7: ["14w04a"],
	8: ["14w04b"],
	9: ["14w05a"],
	10: ["14w06a"],
	11: ["14w07a"],
	12: ["14w08a"],
	14: ["14w11a"],
	15: ["14w17a"],
	16: ["14w18b"],
	17: ["14w19a"],
	18: ["14w20a"],
	19: ["14w21a"],
	20: ["14w21b"],
	21: ["14w25a"],
	22: ["14w25b"],
	23: ["14w26a"],
	24: ["14w26b"],
	25: ["14w26c"],
	26: ["14w27a", "14w27b"],
	27: ["14w28a"],
	28: ["14w28b"],
	29: ["14w29a"],
	30: ["14w30a"],
	31: ["14w30c"],
	32: ["14w31a"],
	33: ["14w32a"],
	34: ["14w32b"],
	35: ["14w32c"],
	36: ["14w32d"],
	37: ["14w33a"],
	38: ["14w33b"],
	39: ["14w33c"],
	40: ["14w34a"],
	41: ["14w34b"],
	42: ["14w34c"],
	43: ["14w34d"],
	44: ["1.8-pre1"],
	45: ["1.8-pre2"],
	46: ["1.8-pre3"],
	47: ["1.8", "1.8.1", "1.8.2", "1.8.3", "1.8.4", "1.8.5", "1.8.6", "1.8.7", "1.8.8", "1.8.9"],
	48: ["15w14a"],
	49: ["15w31a"],
	50: ["15w31b"],
	51: ["15w31c"],
	52: ["15w32a"],
	53: ["15w32b"],
	54: ["15w32c"],
	55: ["15w33a"],
	56: ["15w33b"],
	57: ["15w33c"],
	58: ["15w34a"],
	59: ["15w34b"],
	60: ["15w34c"],
	61: ["15w34d"],
	62: ["15w35a"],
	63: ["15w35b"],
	64: ["15w35c"],
	65: ["15w35d"],
	66: ["15w35e"],
	67: ["15w36a"],
	68: ["15w36b"],
	69: ["15w36c"],
	70: ["15w36d"],
	71: ["15w37a"],
	72: ["15w38a"],
	73: ["15w38b"],
	74: ["15w39c"],
	75: ["15w40a"],
	76: ["15w40b"],
	77: ["15w41a"],
	78: ["15w41b"],
	79: ["15w42a"],
	80: ["15w43a"],
	81: ["15w43b"],
	82: ["15w43c"],
	83: ["15w44a"],
	84: ["15w44b"],
	85: ["15w45a"],
	86: ["15w46a"],
	87: ["15w47a"],
	88: ["15w47b"],
	89: ["15w47c"],
	90: ["15w49a"],
	91: ["15w49b"],
	92: ["15w50a"],
	93: ["15w51a"],
	94: ["15w51b"],
	95: ["16w02a"],
	96: ["16w03a"],
	97: ["16w04a"],
	98: ["16w05a"],
	99: ["16w05b"],
	100: ["16w06a"],
	101: ["16w07a"],
	102: ["16w07b"],
	103: ["1.9-pre1"],
	104: ["1.9-pre2"],
	105: ["1.9-pre3"],
	106: ["1.9-pre4"],
	107: ["1.9"],
	108: ["1.9.1-pre2"],
	109: ["1.9.2", "16w14a", "16w15a", "16w15b", "1.9.3-pre1", "1.9.3-pre3", "1.9.3", "1.9.4"],
	110: ["1.9.3-pre2"],
	201: ["16w20a"],
	202: ["16w21a"],
	203: ["16w21b"],
	204: ["1.10-pre1"],
	205: ["1.10-pre2"],
	210: ["1.10", "1.10.1", "1.10.2"],
	301: ["16w32a"],
	302: ["16w32b"],
	303: ["16w33a"],
	304: ["16w35a"],
	305: ["16w36a"],
	306: ["16w38a"],
	307: ["16w39a"],
	308: ["16w39b"],
	309: ["16w39c"],
	310: ["16w40a"],
	311: ["16w41a"],
	312: ["16w42a"],
	313: ["16w43a", "16w44a"],
	314: ["1.11-pre1"],
	315: ["1.11"],
	316: ["16w50a", "1.11.1", "1.11.2"],
	317: ["17w06a"],
	318: ["17w13a"],
	319: ["17w13b"],
	320: ["17w14a"],
	321: ["17w15a"],
	322: ["17w16a"],
	323: ["17w16b"],
	324: ["17w17a"],
	325: ["17w17b"],
	326: ["17w18a"],
	327: ["17w18b"],
	328: ["1.12-pre1"],
	329: ["1.12-pre2"],
	330: ["1.12-pre3"],
	331: ["1.12-pre4"],
	332: ["1.12-pre5"],
	333: ["1.12-pre6"],
	334: ["1.12-pre7"],
	335: ["1.12"],
	336: ["17w31a"],
	337: ["1.12.1-pre1"],
	338: ["1.12.1"],
	339: ["1.12.2-pre1", "1.12.2-pre2"],
	340: ["1.12.2"],
	341: ["17w43a"],
	342: ["17w43b"],
	343: ["17w45a"],
	344: ["17w45b"],
	345: ["17w46a"],
	346: ["17w47a"],
	347: ["17w47b"],
	348: ["17w48a"],
	349: ["17w49a"],
	350: ["17w49b"],
	351: ["17w50a"],
	352: ["18w01a"],
	353: ["18w02a"],
	354: ["18w03a"],
	355: ["18w03b"],
];
