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
 * Copyright: 2017-2020 sel-project
 * License: LGPL-3.0
 * Authors: Kripth
 * Source: $(HTTP github.com/sel-project/sel-server/sel/server/client.d, sel/server/client.d)
 */
module sel.server.client;

import core.atomic : atomicOp;

import std.json : JSONValue;
import std.socket : Address;
import std.uuid : UUID;

enum InputMode {

	keyboard,
	touch,
	controller,

}

/**
 * Represents a generic game client.
 */
class Client {

	// same as hncom's
	public enum ubyte BEDROCK = 0;
	public enum ubyte JAVA = 1;

	protected enum VERSION_MINECRAFT = "Minecraft";
	protected enum VERSION_JAVA = "Minecraft: Java Edition";
	protected enum VERSION_EDU = "Minecraft: Education Edition";

	private static shared uint _id;

	public immutable uint id;
	public immutable ubyte type;
	public immutable uint protocol;

	private Address _address;
	private string _username;
	private UUID _uuid;
	
	public immutable string gameName;
	public immutable string gameVersion;
	public immutable string game;

	public string serverIp;
	public ushort serverPort;

	public string skinName;
	public immutable(ubyte)[] skinData;
	public string skinGeometryName;
	public immutable(ubyte)[] skinGeometryData;
	public immutable(ubyte)[] skinCape;
	public InputMode inputMode = InputMode.keyboard;
	public string language;

	public JSONValue gameData;

	public void delegate(ubyte[]) handler;

	public shared this(ubyte type, uint protocol, Address address, string username, UUID uuid, string gameName, string gameVersion) {
		this.id = atomicOp!"+="(_id, 1);
		this.type = type;
		this.protocol = protocol;
		this._address = cast(shared)address;
		this._username = username;
		this._uuid = cast(shared)uuid;
		this.gameName = gameName;
		this.gameVersion = gameVersion;
		this.game = gameName ~ " " ~ gameVersion;
		//TODO set handler
	}

	/**
	 * Gets the client's address. May be either an ipv4 or ipv6, depending on
	 * the address where the server is binded to.
	 * Example:
	 * ---
	 * if(cast(InternetAddress)client.address) {
	 *    writeln(client, " is ipv6");
	 * }
	 * ---
	 */
	public shared pure nothrow @property @trusted @nogc Address address() {
		return cast()this._address;
	}

	/**
	 * Gets the client's username.
	 */
	public shared pure nothrow @property @safe @nogc string username() {
		return this._username;
	}

	/**
	 * Gets the client's UUID.
	 */
	public shared pure nothrow @property @safe @nogc UUID uuid() {
		return cast()this._uuid;
	}

	public abstract shared synchronized void send(ubyte[] packet);

	public abstract shared synchronized void directSend(ubyte[] payload);

	public final shared void disconnect(string message, bool translation=false, string[] params=[]) {
		this.disconnectImpl(message, translation, params);
	}

	public final shared void disconnect(string message, string[] params) {
		this.disconnect(message, true, params);
	}

	protected abstract shared void disconnectImpl(string message, bool translation, string[] params);

	public shared string toString() {
		return "Client(" ~ this.username ~ ", " ~ this.uuid.toString() ~ ")";
	}

}
