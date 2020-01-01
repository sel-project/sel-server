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
 * Source: $(HTTP github.com/sel-project/sel-server/sel/server/package.d, sel/server/package.d)
 */
module sel.server;

public import sel.server.bedrock : bedrockSupportedProtocols, BedrockServer, BedrockServerImpl;
public import sel.server.client : Client, InputMode;
public import sel.server.java : JavaServer, JavaClient, javaSupportedProtocols = supportedProtocols;
public import sel.server.query : Query;
public import sel.server.server : ServerInfo, Handler;
