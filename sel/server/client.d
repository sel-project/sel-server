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
module sel.server.client;

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

	private static shared uint _id;

	public immutable uint id;
	public immutable uint protocol;

	private Address _address;
	private string _username;
	private UUID _uuid;

	public string serverIp;
	public ushort serverPort;

	public string skinName;
	public ubyte[] skinData;
	public string gameVersion;
	public long deviceOS;
	public string deviceModel;
	public InputMode inputMode = InputMode.keyboard;
	public string language = "en_US";

	public void delegate(ubyte[]) handler;

	public shared this(uint protocol, Address address, string username, UUID uuid) {
		this.id = _id;
		_id = _id + 1;
		this.protocol = protocol;
		this._address = cast(shared)address;
		this._username = username;
		this._uuid = cast(shared)uuid;
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
	public shared pure nothrow @property @safe @nogc const UUID uuid() {
		return cast()this._uuid;
	}

	public abstract shared synchronized void send(ubyte[] packet);

	public abstract shared synchronized void directSend(ubyte[] payload);

	public shared string toString() {
		return "Client(" ~ this.username ~ ", " ~ this.uuid.toString() ~ ")";
	}

}
