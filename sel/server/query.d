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
module sel.server.query;

import std.array : Appender;
import std.bitmanip : nativeToLittleEndian;
import std.conv : to;
import std.datetime.stopwatch : StopWatch;
import std.string : join;

import sel.server.util;

class Query {

	private shared ServerInfo info;

	public shared string software = "sel-server";
	public shared string[] plugins;

	public shared string[] players;

	public shared this(shared ServerInfo info) {
		this.info = info;
	}

	public class Handler {

		private immutable string game;
		private immutable string ip;
		private immutable ushort port;

		private int challengeToken = 1;
		private string[int] sessions;
		private StopWatch sessionTimer;

		private immutable(ubyte)[] basicQuery, fullQuery;
		private StopWatch basicTimer, fullTimer;
		private long lastBasic = long.min, lastFull = long.min;

		public this(string game, string ip, ushort port) {
			this.game = game;
			this.ip = ip;
			this.port = port;
			this.sessionTimer.start();
			this.basicTimer.start();
			this.fullTimer.start();
		}
		
		public ubyte[] handle(ubyte[] payload) {
			if(payload.length >= 5) {
				if(payload[0] == 0) {
					// query request
					if(payload.length == 13) {
						mixin(createHandler("full", 5_000));
					} else {
						mixin(createHandler("basic", 1_000));
					}
				} else if(payload[0] == 9) {
					// login
					if(this.sessionTimer.peek().split!"msecs"().msecs > 30_000) {
						this.sessions.clear();
						this.sessionTimer.reset();
					}
					this.sessions[this.challengeToken] = ""; //TODO store the address
					return ubyte(9) ~ payload[1..5] ~ cast(ubyte[])to!string(this.challengeToken++) ~ ubyte(0);
				}

			}
			return [];
		}

		private void regenerateBasicQuery() {
			auto appender = createAppender();
			appender.put(info.motd.raw);
			appender.put(info.gametype);
			appender.put(info.map);
			appender.put(to!string(info.online));
			appender.put(to!string(info.max));
			appender.put(cast(ubyte[])nativeToLittleEndian(this.port));
			appender.put(this.ip);
			this.basicQuery = appender.data.idup;
		}

		private void regenerateFullQuery() {
			auto appender = createAppender();
			appender.put("splitnum", "\x80");
			appender.put("hostname", info.motd.raw);
			appender.put("gametype", info.gametype);
			appender.put("game_id", this.game);
			appender.put("version", "?");
			appender.put("plugins", software ~ (plugins.length ? ": " ~ plugins.join("; ") : ""));
			appender.put("map", info.map);
			appender.put("numplayers", to!string(info.online));
			appender.put("maxplayers", to!string(info.max));
			appender.put("hostport", to!string(this.port));
			appender.put("hostip", this.ip);
			appender.put("\0\1player_\0");
			foreach(player ; players) {
				appender.put(player);
			}
			appender.appender.put(ubyte(0));
			this.fullQuery = appender.data.idup;
		}

	}

}

private auto createAppender() {

	struct _ {

		public Appender!(ubyte[]) appender;

		void put(ubyte[] bytes) {
			this.appender.put(bytes);
		}

		void put(string value) {
			this.appender.put(cast(ubyte[])value);
			this.appender.put(ubyte(0));
		}

		void put(string key, string value) {
			this.put(key);
			this.put(value);
		}

		alias appender this;

	}

	return _();

}

private string createHandler(string type, uint time) {
	import std.string : capitalize;
	return "
		immutable peek = this." ~ type ~ "Timer.peek().split!`msecs`().msecs;
		if(peek > this.last" ~ capitalize(type) ~ " + " ~ to!string(time) ~ ") {
			this.regenerate" ~ capitalize(type) ~ "Query();
			this.last" ~ capitalize(type) ~ " = peek;
			this." ~ type ~ "Timer.reset();
		}
		return this." ~ type ~ "Query.dup;
	";
}
