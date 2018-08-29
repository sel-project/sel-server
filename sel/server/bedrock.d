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

import std.conv : to;
import std.socket : Address, InternetAddress, AddressFamily;
import std.uuid : UUID;
import std.zlib : Compress, UnCompress, HeaderFormat, ZlibException;

import kiss.event : EventLoop;
import kiss.net.UdpSocket : UdpSocket;

import sel.protocols : bedrockProtocols;
import sel.raknet.handler : RaknetHandler;
import sel.raknet.packet : RaknetAddress = Address, UnconnectedPing, UnconnectedPong, OpenConnectionRequest1, OpenConnectionReply1, OpenConnectionRequest2, OpenConnectionReply2, Ping, Pong, ClientCancelConnection, ClientConnect, ServerHandshake, ClientHandshake;
import sel.server.server : GameServer, Handler;
import sel.server.util : ServerInfo, Client;

import std.stdio;

class BedrockServer : GameServer {

	private enum __protocols = bedrockProtocols.keys;

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
						writeln("PING! ", ping.time);
						this.raknetHandler.send(new Pong(ping.time).encode());
						break;
					case ClientCancelConnection.ID:
						writeln("CLOSED!");
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
			writeln(cast(string)buffer);
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
							//TODO handle compressed body
							writeln("NEED TO HANDLE COMPRESSED BODY");
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

		class BedrockClient : Client {

			this(Address address, string username, UUID uuid) {
				super(address, username, uuid);
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
