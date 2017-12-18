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
module sel.server.bedrock;

import core.thread : Thread;

import std.algorithm : sort, canFind, all, max;
import std.base64 : Base64, Base64Impl, Base64Exception;
import std.bitmanip : peek;
import std.concurrency : spawn, Tid, sendc = send, receiveTimeout, receiveOnly;
import std.conv : to;
import std.datetime : dur;
import std.datetime.stopwatch : StopWatch;
import std.json : JSONValue, JSON_TYPE, parseJSON, JSONException;
import std.socket : Address, AddressFamily, InternetAddress, Internet6Address, Socket, UdpSocket, SocketOptionLevel, SocketOption;
import std.string : indexOf, lastIndexOf;
import std.system : Endian;
import std.typecons : Tuple;
import std.uuid : UUID, parseUUID, UUIDParsingException;
import std.zlib : Compress, UnCompress, ZlibException;

import sel.server.client : Client, InputMode;
import sel.server.query : Query;
import sel.server.util;
import sel.stream;

import sul.protocol.raknet8.encapsulated : ClientConnect, ServerHandshake, ClientHandshake, ClientCancelConnection, ConnectedPing = Ping, ConnectedPong = Pong;
import sul.protocol.raknet8.types : RaknetAddress = Address;
import sul.protocol.raknet8.unconnected;
import sul.utils.var : varuint;

debug import std.stdio : writeln;

enum __magic = cast(ubyte[16])x"00 FF FF 00 FE FE FE FE FD FD FD FD 12 34 56 78";

public enum string[][uint] bedrockSupportedProtocols = [
	137u: ["1.2.0", "1.2.1", "1.2.2", "1.2.3"],
	141u: ["1.2.5"],
	150u: ["1.2.6"],
	160u: ["1.2.7"],
];

abstract class BedrockServer : GenericServer {

	public shared this(shared ServerInfo info, uint[] protocols, uint[] supportedProtocols) {
		super(info, protocols, supportedProtocols);
	}
	
	public override shared pure nothrow @property @safe @nogc ushort defaultPort() {
		return ushort(19132);
	}

}

alias BedrockServerImpl(string[][uint] supportedProtocols) = BedrockServerImpl!(supportedProtocols.keys);

template BedrockServerImpl(uint[] rawSupportedProtocols) /*if(checkProtocols(rawSupportedProtocols, bedrockSupportedProtocols.keys).length)*/ {

	enum supportedProtocols = checkProtocols(rawSupportedProtocols, bedrockSupportedProtocols.keys);

	class BedrockServerImpl : BedrockServer {
	
		public shared this(shared ServerInfo info, uint[] protocols=supportedProtocols) {
			super(info, protocols, supportedProtocols);
		}
		
		protected override shared void startImpl(Address address, shared Handler handler, shared Query query) {
			Socket socket = new UdpSocket(address.addressFamily);
			socket.blocking = true;
			socket.bind(address);
			auto shared_socket = cast(shared)socket;
			if(address.addressFamily == AddressFamily.INET) {
				new Thread({ try { this.receivePackets!true(shared_socket, handler, query); } catch(Throwable t){ debug{writeln(t);} }}).start();
			} else {
				assert(0, "Unsupported address family: " ~ address.addressFamily.to!string);
			}
		}
		
		protected shared void receivePackets(bool ipv4)(shared Socket socket, shared Handler handler, shared Query query) {
			debug Thread.getThis().name = "bedrock_server.receive_packets";
			auto handlerThread = cast(shared)spawn(&this.startHandler); // used to handle packets instead of doing it in the socket/uncompression thread
			auto compressionManager = cast(shared)spawn(&this.startCompressionManager);
			immutable protocolsString = to!string(this.protocols[$-1]) ~ ";" ~ bedrockSupportedProtocols[this.protocols[$-1]][0];
			static if(ipv4) {
				alias Id = Tuple!(uint, ushort);
			} else {
				alias Id = Tuple!(ubyte[16], ushort);
			}
			UdpStream stream = new UdpStream(cast()socket);
			immutable bool acceptQueries = query !is null;
			Query.Handler qhandler;
			if(acceptQueries) {
				with(stream.socket.localAddress) qhandler = (cast()query).new Handler("MINECRAFTPE", toAddrString(), to!ushort(toPortString()));
			}
			shared(RaknetSession)[Id] sessions;
			Address _address;
			while(true) {
				ubyte[] buffer = stream.receiveFrom(_address);
				if(buffer.length) {
					static if(ipv4) {
						InternetAddress address = cast(InternetAddress)_address;
					} else {
						Internet6Address address = cast(Internet6Address)_address;
					}
					Id id = Id(address.addr, address.port);
					auto session = id in sessions;
					if(session && !(*session).closed) {
						(*session).handle(buffer);
					} else {
						// not a session
						switch(buffer[0]) {
							case Ping.ID:
								Ping ping = Ping.fromBuffer(buffer);
								stream.sendTo(new Pong(ping.pingId, 0, __magic, "MCPE;" ~ this.info.motd ~ ";" ~ protocolsString ~ ";" ~ to!string(this.info.online) ~ ";" ~ to!string(this.info.max)).encode(), address);
								break;
							case OpenConnectionRequest1.ID:
								auto packet = OpenConnectionRequest1.fromBuffer(buffer);
								if(packet.mtu.length > 448) {
									// do not allow connection when mtu is too small
									stream.sendTo(new OpenConnectionReply1(__magic, 0, false, cast(ushort)packet.mtu.length).encode(), address);
									// session is not created yet
								}
								break;
							case OpenConnectionRequest2.ID:
								auto packet = OpenConnectionRequest2.fromBuffer(buffer);
								if(packet.mtuLength > 448 && packet.mtuLength < 1536) {
									stream.sendTo(new OpenConnectionReply2(__magic, 0, createAddress(address), packet.mtuLength, false).encode(), address);
									// every packet for this session is not encapsulated
									sessions[id] = new shared RaknetSession(this.protocols, address, new RaknetStream(stream.socket, address, packet.mtuLength), handler, handlerThread, compressionManager);
								}
								break;
							default:
								if(acceptQueries && buffer.length >= 2 && buffer[0] == 254 && buffer[1] == 253) {
									auto data = qhandler.handle(buffer[2..$]);
									if(data.length) {
										stream.sendTo(data, address);
									}
								}
								break;
						}
					}
				}
			}
		}
		
		private shared void startHandler() {
			debug Thread.getThis().name = "bedrock_server.handler";
			while(true) {
				try {
					auto data = receiveOnly!(shared Client, immutable(ubyte)[])();
					data[0].handler(data[1].dup);
				} catch(Throwable t) {
					debug writeln(t);
				}
			}
		}

		private shared void startCompressionManager() {
			debug Thread.getThis().name = "bedrock_server.compression_manager";
			while(true) {
				try {
					auto client = receiveOnly!(shared BedrockClient)();
					client.startThreads();
				} catch(Throwable t) {
					debug writeln(t);
				}
			}
		}
		
	}

	class RaknetSession {
		
		private immutable(uint)[] protocols;
		
		private shared Address address;
		private shared RaknetStream stream;
		
		private shared Handler handler;
		public shared Tid handlerThread;
		public shared Tid compressionManager;
		
		private shared bool _closed = false;
		
		private shared void delegate(ubyte[]) shared handleFunction;
		
		private BedrockClient client;
		
		public shared this(immutable(uint)[] protocols, Address address, RaknetStream stream, shared Handler handler, shared Tid handlerThread, shared Tid compressionManager) {
			this.protocols = protocols;
			stream.acceptSplit = false;
			this.address = cast(shared)address;
			this.stream = cast(shared)stream;
			this.handler = handler;
			this.handlerThread = handlerThread;
			this.compressionManager = compressionManager;
			this.handleFunction = &this.handleClientConnect;
		}
		
		public shared nothrow @property @safe @nogc bool closed() {
			return this._closed;
		}
		
		public shared void handle(ubyte[] buffer) {
			buffer = (cast()this.stream).handle(buffer);
			if(buffer.length) {
				switch(buffer[0]) {
					case ConnectedPing.ID:
						(cast()this.stream).send(new ConnectedPong(ConnectedPing.fromBuffer(buffer).time).encode());
						//TODO use to calculate latency
						break;
					case ClientCancelConnection.ID:
						this.close();
						break;
					default:
						this.handleFunction(buffer);
				}
			}
		}
		
		private shared void handleClientConnect(ubyte[] buffer) {
			if(buffer[0] == ClientConnect.ID) {
				auto packet = ClientConnect.fromBuffer(buffer);
				auto stream = cast()this.stream;
				stream.send(new ServerHandshake(createAddress(cast()this.address), cast(ushort)stream.mtu, cast()systemAddresses, packet.pingId, 0).encode());
				this.handleFunction = &this.handleClientHandshake;
			}
		}
		
		private shared void handleClientHandshake(ubyte[] buffer) {
			if(buffer[0] == ClientHandshake.ID) {
				auto packet = ClientHandshake.fromBuffer(buffer);
				(cast()this.stream).acceptSplit = true;
				this.handleFunction = &this.handleLogin;
			}
		}
		
		private shared void handleLogin(ubyte[] buffer) {
			switch(buffer[0]) {
				case 254:
					// 0.15, 1.0, 1.1, 1.2 (container)
					if(buffer.length > 6) {
						this.handleFunction = &this.handleNothing; // avoid handling the login more than once
						if(buffer[1] == 0x78) {
							// compressed (1.1, 1.2)
							// uncompress
							// do protocol controls
							// handle non-compressed login body
							spawn(&this.handleCompressedBody, buffer[1..$].idup, false);
							break;
						} else if(buffer[1] == 1 || buffer[1] == 6) {
							// login or batch packet (1.0)
							(cast()this.stream).send(cast(ubyte[])[254, 2, 0, 0, 0, 1]);
						}
					}
					this.close();
					break;
				case 142:
					// 0.14 (container)
					(cast()this.stream).send(cast(ubyte[])[142, 144, 0, 0, 0, 1]);
					this.close();
					break;
				case 143:
				case 146:
					// 0.12, 0.13 (login and batch)
					(cast()this.stream).send(cast(ubyte[])[144, 0, 0, 0, 1]);
					this.close();
					break;
				case 177:
				case 130:
					// 0.11 (login)
					// 0.8, 0.9, 0.10 (login)
					(cast()this.stream).send(cast(ubyte[])[131, 0, 0, 0, 1]);
					this.close();
					break;
				default:
					this.close();
					break;
			}
		}
		
		private shared void handleCompressedBody(immutable(ubyte)[] payload, bool bodyCompressed) {
			debug Thread.getThis().name = "bedrock_client@?";
			ubyte[][] packets;
			try {
				packets = uncompressPackets(payload);
			} catch(ZlibException) {
				this.close();
				return;
			}
			if(packets.length == 1 && packets[0].length > 5 && packets[0][0] == 1) {
				ubyte[] login = packets[0];
				immutable protocol = this.validateProtocol(login[1..5]);
				if(protocol != 0) {
					this.handleLoginBody(protocol, login[5..$].idup, bodyCompressed);
					return;
				}
			}
			// wrong packet or wrong protocol
			this.close();
		}
		
		private shared void handleLoginBody(uint protocol, immutable(ubyte)[] _payload, bool compressed) {
			ubyte[] payload = _payload.dup;
			immutable edition = (){
				if(protocol < 8 || protocol >= 120) {
					// vanilla by default
					return 0;
				} else {
					immutable ret = payload[0];
					payload = payload[1..$];
					return ret;
				}
			}();
			if(varuint.fromBuffer(payload) == payload.length && payload.length) {
				if(compressed) {
					try {
						UnCompress uc = new UnCompress();
						payload = cast(ubyte[])uc.uncompress(payload);
						payload ~= cast(ubyte[])uc.flush();
					} catch(ZlibException) {
						this.close();
						return;
					}
				}
				size_t index = 0;
				string readBody() {
					if(index + 4 < payload.length) {
						immutable length = peek!(uint, Endian.littleEndian)(payload, &index);
						if(length + index <= payload.length) {
							return cast(string)payload[index..index+=length];
						}
					}
					return "";
				}
				JSONValue chainJSON;
				try chainJSON = parseJSON(readBody()); // {"chain":["a.b.c"]}
				catch(JSONException) {}
				if(chainJSON.type == JSON_TYPE.OBJECT) {
					auto chain = "chain" in chainJSON;
					if(chain && chain.type == JSON_TYPE.ARRAY && chain.array.length && chain.array.length <= 3 && chain.array.all!(a => a.type == JSON_TYPE.STRING)) {
						try chainJSON = parseJWT(chain.array[$-1].str);
						catch(JSONException) return this.close();
						if(chainJSON.type == JSON_TYPE.OBJECT) {
							auto extraData = "extraData" in chainJSON;
							if(extraData && extraData.type == JSON_TYPE.OBJECT) {
								auto displayName = "displayName" in *extraData;
								auto identity = "identity" in *extraData;
								if(displayName && identity && displayName.type == JSON_TYPE.STRING && identity.type == JSON_TYPE.STRING) {
									UUID uuid;
									try uuid = parseUUID(identity.str);
									catch(UUIDParsingException) return this.close();
									JSONValue clientData;
									try clientData = parseJWT(readBody());
									catch(JSONException) return this.close();
									if(clientData.type == JSON_TYPE.OBJECT) {
										this.client = (){
											final switch(protocol) {
												foreach(p ; TupleOf!supportedProtocols) {
													case p:
													return cast(shared BedrockClient)new shared BedrockClientOf!p(this, protocol, displayName.str, uuid);
												}
											}
										}();
										//TODO validate username
										this.handleFunction = &this.handlePlay;
										this.client.parseClientData(clientData);
										this.handler.onClientJoin(this.client);
										return;
									}
								}
							}
						}
					}
				}
			}
			// generic failure
			this.close();
		}
		
		private shared void handlePlay(ubyte[] buffer) {
			if(buffer.length > 1 && buffer[0] == 254) {
				this.client.handle(buffer[1..$]);
			}
		}
		
		private shared void handleNothing(ubyte[] buffer) {}
		
		/**
		 * Returns: the number of the protocol indicated by the client if accepted by the server or 0
		 */
		private shared uint validateProtocol(ubyte[] data) {
			uint protocol = peek!uint(data, 0);
			ubyte[] packet = cast(ubyte[])[2, 0, 0, 0, 0, 0, 0]; // id (byte), padding (byte[2]), code (int)
			if(!this.protocols.canFind(protocol)) {
				if(protocol > this.protocols[$-1]) packet[$-1] = 2; // outdated server
				else packet[$-1] = 1; // outdated client
				//this.close();
				protocol = 0;
			}
			// compress everything! (since protocol 110)
			Compress compress = new Compress(1);
			packet = cast(ubyte[])compress.compress(varuint.encode(packet.length.to!uint) ~ packet);
			(cast()this.stream).send(ubyte(254) ~ packet);
			return protocol;
		}
		
		/**
		 * Removes the session.
		 */
		private shared void close() {
			if(!this._closed) {
				this._closed = true;
				this.handleFunction = &this.handleNothing; // do not handle anymore
				if(this.client !is null) {
					this.client.stopThreads();
					this.handler.onClientLeft(this.client);
				}
			}
		}
		
	}

	class BedrockClient : Client {
		
		protected shared RaknetSession raknetSession;

		public shared Tid uncompression, compression;
		
		public shared this(uint protocol, shared RaknetSession session, string username, UUID uuid) {
			super(protocol, cast()session.address, username, uuid);
			this.raknetSession = session;
			sendc(cast()raknetSession.compressionManager, this);
		}

		public shared void startThreads() {
			this.uncompression = cast(shared)spawn(&this.startUncompression);
			this.compression = cast(shared)spawn(&this.startCompression);
		}
		
		public shared void stopThreads() {
			// crashes the threads
			sendc(cast()this.uncompression, "");
			sendc(cast()this.compression, "");
		}
		
		public shared void parseClientData(JSONValue json) {
			auto skinName = "SkinId" in json;
			auto skinData = "SkinData" in json;
			auto gameVersion = "GameVersion" in json;
			auto deviceOS = "DeviceOS" in json;
			auto deviceModel = "DeviceModel" in json;
			auto inputMode = "CurrentInputMode" in json;
			auto language = "LanguageCode" in json;
			if(skinName && skinName.type == JSON_TYPE.STRING) {
				this.skinName = skinName.str;
			}
			if(skinData && skinData.type == JSON_TYPE.STRING) {
				immutable str = skinData.str;
				//TODO check length
				try this.skinData = cast(shared)Base64.decode(skinData.str);
				catch(Base64Exception) {}
			}
			if(gameVersion && gameVersion.type == JSON_TYPE.STRING) {
				this.gameVersion = gameVersion.str;
			}
			if(deviceOS && deviceOS.type == JSON_TYPE.INTEGER) {
				this.deviceOS = deviceOS.integer;
			}
			if(deviceModel && deviceModel.type == JSON_TYPE.STRING) {
				this.deviceModel = deviceModel.str;
			}
			if(inputMode && inputMode.type == JSON_TYPE.INTEGER) {
				this.inputMode = (){
					switch(inputMode.integer) {
						case 0: return InputMode.controller;
						case 1: return InputMode.touch;
						default: return InputMode.keyboard;
					}
				}();
			}
			if(language && language.type == JSON_TYPE.STRING) {
				this.language = language.str;
			}
		}

		public shared void handle(ubyte[] buffer) {
			sendc(cast()this.uncompression, buffer.idup);
		}

		private shared void startUncompression() {
			while(true) {
				foreach(packet ; uncompressPackets(receiveOnly!(immutable(ubyte)[])())) {
					sendc(cast()this.raknetSession.handlerThread, cast(shared Client)this, packet.idup);
				}
			}
		}
		
		/**
		 * Sends a disconnection message to the client and closes
		 * the session.
		 */
		public shared void disconnect(string message) {
			this.send(this.createDisconnect(message));
			this.raknetSession.close();
		}
		
		protected abstract shared ubyte[] createDisconnect(string message);
		
		/**
		 * Sends a game packet to the client.
		 */
		public override shared synchronized void send(ubyte[] packet) {
			//writeln("sending ", packet[0]);
			// compress body in another thread but maintain order
			sendc(cast()this.compression, packet.idup);
		}
		
		public override shared synchronized void directSend(ubyte[] payload) {
			// assuming that the content has already been compressed
			(cast()this.raknetSession.stream).send(ubyte(254) ~ payload);
		}
		
		private shared void startCompression() {
			while(true) {
				ubyte[][] data;
				while(receiveTimeout(dur!"msecs"(0), (immutable(ubyte)[] payload){ data ~= payload.dup; }, (string close){ throw new Exception(""); })) {}
				if(data.length) {
					sendData(data);
				}
			}
		}
		
		protected shared void sendData(ubyte[][] packets) {
			// always compress the body
			foreach(packet ; this.compressPackets(packets)) {
				(cast()this.raknetSession.stream).send(ubyte(254) ~ packet);
			}
		}

		//TODO do not compress too much data
		protected shared ubyte[][] compressPackets(ubyte[][] packets) {
			//writeln("compressing ", packets.length, " toghether (", totalLength(packets), ")");
			ubyte[][] compressed = new ubyte[][1];
			size_t length = 0;
			foreach(packet ; packets) {
				compressed[$-1] ~= varuint.encode(packet.length.to!uint + 2); // 2 bytes of padding
				compressed[$-1] ~= packet[0];
				compressed[$-1] ~= [ubyte(0), ubyte(0)]; // 2-bytes padding
				compressed[$-1] ~= packet[1..$];
				if((length += packet.length) > 500_000) {
					// do not compress more than 500 MB
					compressed.length++;
					length = 0;
				}
			}
			foreach(ref buffer ; compressed) {
				Compress compress = new Compress();
				buffer = cast(ubyte[])compress.compress(buffer);
				buffer ~= cast(ubyte[])compress.flush();
			}
			return compressed;
		}
		
	}

	enum uint[uint] same = [
		141u: 160u,
		150u: 160u,
	];

	template BedrockClientOf(uint __protocol) {
		
		static if(same.keys.canFind(__protocol)) {
			
			// they're exactly the same in therm of packets used in
			// the software, may be different in other packets.
			alias BedrockClientOf = BedrockClientOf!(same[__protocol]);
			
		} else {
			
			mixin("import Play = sul.protocol.bedrock" ~ __protocol.to!string ~ ".play;");
			
			class BedrockClientOf : BedrockClient {
				
				public shared this(shared RaknetSession session, uint protocol, string username, UUID uuid) {
					super(protocol, session, username, uuid);
				}
				
				public override shared ubyte[] createDisconnect(string message) {
					return new Play.Disconnect(false, message).encode();
				}
				
				static if(is(typeof(Session.batchId))) {
					
					protected override shared pure nothrow @property @safe @nogc ubyte batchId() {
						return Play.Batch.ID;
					}
					
				}
				
			}
			
		}
		
	}

}

private JSONValue parseJWT(string data) {
	immutable a = data.indexOf(".");
	if(a != -1) {
		immutable z = data.lastIndexOf(".");
		if(a != z) {
			try return parseJSON(cast(string)Base64Impl!('-', '_', Base64.NoPadding).decode(data[a+1..z]));
			catch(Base64Exception) {}
		}
	}
	return JSONValue.init;
}

private ubyte[][] uncompressPackets(inout(ubyte)[] payload) {
	UnCompress uc = new UnCompress();
	auto data = cast(ubyte[])uc.uncompress(payload);
	data ~= cast(ubyte[])uc.flush();
	ubyte[][] packets;
	size_t index, length;
	while((length = varuint.decode(data, &index)) >= 3 && length <= data.length - index) {
		// packets have a 2-bytes padding after the id
		packets ~= (data[index..index+1] ~ data[index+3..index+length]);
		index += length;
	}
	return packets;
}

private __gshared RaknetAddress[10] systemAddresses;

shared static this() {
	foreach(ref address ; systemAddresses) {
		address.type = 4;
	}
}

RaknetAddress createAddress(Address address) {
	RaknetAddress ret;
	auto v4 = cast(InternetAddress)address;
	if(v4) {
		ret.type = 4;
		ret.ipv4 = v4.addr ^ uint.max;
		ret.port = v4.port;
	} else {
		auto v6 = cast(Internet6Address)address;
		assert(v6 !is null);
		ret.type = 6;
		ret.ipv6 = v6.addr; //TODO mask with 0xff
		ret.port = v6.port;
	}
	return ret;
}

private size_t totalLength(ubyte[][] packets) {
	size_t length = 0;
	foreach(packet ; packets) {
		length += packet.length;
	}
	return length;
}

unittest {

	alias Server = BedrockServerImpl!bedrockSupportedProtocols;

}
