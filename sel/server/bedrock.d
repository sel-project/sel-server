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
import std.socket : Address;
import std.uuid : UUID;

import kiss.event : EventLoop;
import kiss.net.UdpSocket : UdpSocket;

import sel.protocols : bedrockProtocols;
import sel.raknet.packet;
import sel.server.server : GameServer, Handler;
import sel.server.util : ServerInfo, Client;

import std.stdio;

class BedrockServer : GameServer {

	private enum __protocols = bedrockProtocols.keys;

	public this(EventLoop eventLoop, ServerInfo serverInfo, Handler handler, uint[] protocols=__protocols) {
		super(eventLoop, serverInfo, handler, protocols);
	}

	protected override ushort defaultPort() {
		return 19132;
	}

	protected override void hostImpl(Address address) {

		UdpSocket socket = new UdpSocket(this.eventLoop);
		socket.bind(address.toAddrString(), address.toPortString().to!ushort);
		
		void handle(in ubyte[] data, Address address) {
			switch(data[0]) {
				case UnconnectedPing.ID:
					UnconnectedPing ping = new UnconnectedPing();
					ping.autoDecode(cast(ubyte[])data);
					with(this.serverInfo) socket.sendTo(new UnconnectedPong(ping.pingId, 0, "MCPE;" ~ motd.bedrock ~ ";" ~ this.protocols[$-1].to!string ~ ";" ~ bedrockProtocols[this.protocols[$-1]][0] ~ ";" ~ online.to!string ~ ";" ~ max.to!string).autoEncode(), address).writeln;
					break;
				case OpenConnectionRequest1.ID:
					OpenConnectionRequest1 packet = new OpenConnectionRequest1();
					packet.autoDecode(cast(ubyte[])data);
					if(packet.mtu.length > 448 && packet.mtu.length < 4096) {
						// do not allow MTUs that are too small or too big
						socket.sendTo(new OpenConnectionReply1(0, false, packet.mtu.length.to!ushort).autoEncode(), address);
					}
					break;
				case OpenConnectionRequest2.ID:
					OpenConnectionRequest2 packet = new OpenConnectionRequest2();
					packet.autoDecode(cast(ubyte[])data);
					//TODO create RaknetClient
					break;
				default:
					break;
			}
		}

		socket.setReadData(&handle);
		socket.start();

	}

	protected override void kill() {}

	class RaknetClient {

		class BedrockClient : Client {

			this(Address address, string username, UUID uuid) {
				super(address, username, uuid);
			}

		}

	}

}
