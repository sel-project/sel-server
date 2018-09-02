/*
 * Copyright (c) 2017-2018 sel-project
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

import std.algorithm : sort, all;
import std.base64 : Base64, Base64Impl, Base64Exception;
import std.conv : to;
import std.json : JSONValue, parseJSON, JSON_TYPE, JSONException;
import std.socket : Address, InternetAddress, AddressFamily;
import std.string : indexOf, lastIndexOf;
import std.uuid : UUID;
import std.zlib : Compress, UnCompress, HeaderFormat, ZlibException;

import kiss.event : EventLoop;
import kiss.net.UdpSocket : UdpSocket;

import sel.protocols : bedrockProtocols;
import sel.raknet.handler : RaknetHandler;
import sel.raknet.packet : RaknetAddress = Address, UnconnectedPing, UnconnectedPong, OpenConnectionRequest1, OpenConnectionReply1, OpenConnectionRequest2, OpenConnectionReply2, Ping, Pong, ClientCancelConnection, ClientConnect, ServerHandshake, ClientHandshake;
import sel.server.server : GameServer, Handler;
import sel.server.util : ServerInfo, Client;

import soupply.bedrock : Login, PlayStatus, Disconnect;

import xbuffer : Buffer;

import std.stdio;

class BedrockServer : GameServer {

	private enum __protocols = bedrockProtocols.keys.sort.release[7..$]; // since 282 (1.6)

	private static struct Id {

		uint addr;
		ushort port;

	}

	private RaknetClient[Id] clients;

	public this(EventLoop eventLoop, ServerInfo serverInfo, Handler handler, uint[] protocols=__protocols) {
		super(eventLoop, serverInfo, handler, protocols);
	}

	protected override ushort defaultPort() {
		return 19132;
	}

	protected override void hostImpl(Address address) {

		assert(address.addressFamily == AddressFamily.INET, "Only IPv4 supported by Bedrock");

		UdpSocket socket = new UdpSocket(this.eventLoop);
		socket.bind(address.toAddrString(), address.toPortString().to!ushort);
		
		void handle(in ubyte[] data, Address address) {
			InternetAddress ia = cast(InternetAddress)address;
			Id id = Id(ia.addr, ia.port);
			auto client = id in clients;
			if(client) {
				(*client).handle(data);
			} else {
				switch(data[0]) {
					case UnconnectedPing.ID:
						UnconnectedPing ping = new UnconnectedPing();
						ping.decode(data);
						with(this.serverInfo) socket.sendTo(new UnconnectedPong(ping.pingId, 0, "MCPE;" ~ motd.bedrock ~ ";" ~ this.protocols[$-1].to!string ~ ";" ~ bedrockProtocols[this.protocols[$-1]][0] ~ ";" ~ online.to!string ~ ";" ~ max.to!string).encode(), address);
						break;
					case OpenConnectionRequest1.ID:
						OpenConnectionRequest1 packet = new OpenConnectionRequest1();
						packet.decode(data);
						if(packet.mtu.length > 448 && packet.mtu.length < 2048) {
							// do not allow MTUs that are too small or too big
							socket.sendTo(new OpenConnectionReply1(0, false, packet.mtu.length.to!ushort).encode(), address);
						}
						break;
					case OpenConnectionRequest2.ID:
						OpenConnectionRequest2 packet = new OpenConnectionRequest2();
						packet.decode(data);
						if(packet.mtuLength > 448 && packet.mtuLength < 2048) {
							socket.sendTo(new OpenConnectionReply2(0, RaknetAddress(address), packet.mtuLength, false).encode(), address);
							// every packet for this session is now encapsulated
							clients[id] = new RaknetClient(id, address, new RaknetHandler(socket, address, packet.mtuLength));
						}
						break;
					default:
						break;
				}
			}
		}

		socket.setReadData(&handle);
		socket.start();

	}

	public override void stop() {}

	private void removeClient(Id id) {
		this.clients.remove(id);
	}

	class RaknetClient {

		private Id clientId;
		private Address address;

		private RaknetHandler raknetHandler;

		private void delegate(ubyte[]) handleFunction;

		private BedrockClient client;

		this(Id clientId, Address address, RaknetHandler handler) {
			this.clientId = clientId;
			this.address = address;
			this.raknetHandler = handler;
			this.handleFunction = &this.handleClientConnect;
		}

		void handle(in ubyte[] data) {
			ubyte[] buffer = this.raknetHandler.handle(data);
			if(buffer.length) {
				switch(buffer[0]) {
					case Ping.ID:
						Ping ping = new Ping();
						ping.decode(buffer);
						this.raknetHandler.send(new Pong(ping.time).encode());
						break;
					case ClientCancelConnection.ID:
						if(client !is null) handler.onLeft(this.client);
						this.close();
						break;
					default:
						this.handleFunction(buffer);
						break;
				}
			}
		}

		void close() {
			removeClient(this.clientId);
		}
		
		void close(string message) {
			this.raknetHandler.send(new Disconnect(false, message).encode());
			this.close();
		}

		private void handleNothing(ubyte[] buffer) {}

		private void handleClientConnect(ubyte[] buffer) {
			if(buffer[0] == ClientConnect.ID) {
				ClientConnect packet = new ClientConnect();
				packet.decode(buffer);
				this.raknetHandler.send(new ServerHandshake(RaknetAddress(this.address), this.raknetHandler.mtu, systemAddresses, packet.pingId, 0).encode());
				this.handleFunction = &this.handleClientHandshake;
			}
		}

		private void handleClientHandshake(ubyte[] buffer) {
			if(buffer[0] == ClientHandshake.ID) {
				ClientHandshake packet = new ClientHandshake();
				packet.decode(buffer);
				this.raknetHandler.acceptSplit = true;
				this.handleFunction = &this.handleLogin;
			}
		}

		private void handleLogin(ubyte[] buffer) {
			switch(buffer[0]) {
				case 254:
					// 0.15 and newer (container)
					if(buffer.length > 6) {
						this.handleFunction = &this.handleNothing; // avoid handling the login more than once
						if(buffer[1] == 0x78) {
							// compressed (1.1, 1.2)
							// uncompress
							// do protocol controls
							// handle non-compressed login body
							auto packets = uncompress(buffer[1..$]);
							if(packets.length == 1 && packets[0].length && packets[0][0] == Login.ID) {
								Login login = new Login();
								login.decode(packets[0]);
								this.handleLoginPacket(login);
							}
							break;
						} else if(buffer[1] == 1 || buffer[1] == 6) {
							// login or batch packet (1.0)
							this.raknetHandler.send(cast(ubyte[])[254, 2, 0, 0, 0, 1]);
						}
					}
					this.close();
					break;
				case 142:
					// 0.14 (container)
					this.raknetHandler.send(cast(ubyte[])[142, 144, 0, 0, 0, 1]);
					this.close();
					break;
				case 143:
				case 146:
					// 0.12, 0.13 (login and batch)
					this.raknetHandler.send(cast(ubyte[])[144, 0, 0, 0, 1]);
					this.close();
					break;
				case 177:
				case 130:
					// 0.11 (login)
					// 0.8, 0.9, 0.10 (login)
					this.raknetHandler.send(cast(ubyte[])[131, 0, 0, 0, 1]);
					this.close();
					break;
				default:
					this.close();
					break;
			}
		}

		private void handleLoginPacket(Login login) {
			PlayStatus status = new PlayStatus(PlayStatus.OK);
			if(!protocols.contains(login.protocol)) {
				// invalid protocol, disconnect
				if(login.protocol > protocols[$-1]) status.status = PlayStatus.OUTDATED_SERVER;
				else status.status = PlayStatus.OUTDATED_CLIENT;
			}
			this.raknetHandler.send(status.encode());
			if(status.status == PlayStatus.OK) {
				// valid protocol, handle JWT
				bool valid = false;
				try {
					JSONValue chainjson = parseJSON(cast(string)login.body_.chain);
					auto chainptr = "chain" in chainjson;
					if(chainptr && chainptr.type == JSON_TYPE.ARRAY && chainptr.array.length && chainptr.array.length <= 3 && chainptr.array.all!(a => a.type == JSON_TYPE.STRING)()) {
						JSONValue chain = parseJWT(chainptr.array[$-1].str);
						if(chain.type == JSON_TYPE.OBJECT) {

						}
					}
				} catch(JSONException) {
				} catch(Base64Exception) {}
				if(!valid) {
					// data was malformed or invalid, blacklist the client
					//TODO
				}
			} else {
				// send a disconnect packet, just to be sure
				if(status.status == PlayStatus.OUTDATED_SERVER) this.close("disconnectionScreen.outdatedServer");
				else this.close("disconnectionScreen.outdatedClient");
				// connection is also closed
			}
		}

		class BedrockClient : Client {

			public this(Address address, string username, UUID uuid) {
				super(address, username, uuid);
			}

			public override void disconnect(string message) {
				close(message);
			}

		}

	}

}

private static RaknetAddress[10] systemAddresses;

static this() {
	foreach(ref address ; systemAddresses) {
		address.type = 4;
	}
}

private ubyte[][] uncompress(ubyte[] data) {
	UnCompress uc = new UnCompress();
	data = cast(ubyte[])uc.uncompress(data);
	data ~= cast(ubyte[])uc.flush();
	Buffer buffer = new Buffer(data);
	ubyte[][] ret;
	while(buffer.canRead(1)) {
		ret ~= buffer.read!(ubyte[])(buffer.readVar!uint());
	}
	return ret;
}

private JSONValue parseJWT(string data) {
	immutable a = data.indexOf(".");
	if(a != -1) {
		immutable z = data.lastIndexOf(".");
		if(a != z) {
			return parseJSON(cast(string)Base64Impl!('-', '_', Base64.NoPadding).decode(data[a+1..z]));
		}
	}
	return JSONValue.init;
}
