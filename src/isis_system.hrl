%%%-------------------------------------------------------------------
%%% @author Rick Payne <rickp@rossfell.co.uk>
%%% @copyright (C) 2014, Alistair Woodman, California USA <awoodman@netdef.org>
%%% @doc
%%%
%%% This file is part of AutoISIS.
%%%
%%% License:
%%% This code is licensed to you under the Apache License, Version 2.0
%%% (the "License"); you may not use this file except in compliance with
%%% the License. You may obtain a copy of the License at
%%% 
%%%   http://www.apache.org/licenses/LICENSE-2.0
%%% 
%%% Unless required by applicable law or agreed to in writing,
%%% software distributed under the License is distributed on an
%%% "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
%%% KIND, either express or implied.  See the License for the
%%% specific language governing permissions and limitations
%%% under the License.
%%%
%%% @end
%%% Created :  10 March 2014 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------

-record (isis_address, {
	   afi :: atom(),
	   address :: integer(),
	   mask :: integer(),
	   metric :: integer()
	  }).
-type isis_address() :: #isis_address{}.

-record (isis_prefix, {
	   afi :: atom(),
	   address :: integer(),
	   mask_length :: integer()
	  }).
-type isis_prefix() :: #isis_prefix{}.

-record (isis_route_key, {
	   prefix :: isis_prefix(),
	   source = undefined :: isis_prefix() | undefined
	  }).
-type isis_route_key() :: #isis_route_key{}.

-record (isis_route, {
	   route :: isis_route_key(),
	   nexthops = [] :: [integer()],
	   ifindexes = [] :: [integer()],
	   metric :: integer()
	  }).
-type isis_route() :: #isis_route{}.

-record (isis_interface, {
	   name :: string(),
	   mac :: binary(),
	   interface_module :: atom(),
	   mode = broadcast :: broadcast | point_to_multipoint,
	   metric = 10 :: integer(),
	   flags :: integer(),
	   enabled = false :: atom(),
	   status :: integer(),
	   bandwidth :: integer(),
	   pid :: pid(),
	   addresses = [] :: [isis_address()],
	   ifindex :: integer(),
	   mtu :: integer(),
	   mtu6 :: integer()
	  }).
-type isis_interface() :: #isis_interface{}.

%% An isis_circuit is either an interface, of a p2p or p2mp
-record(isis_circuit, {
	  name :: tuple(), %% {interface, Name} | {ipv6, address},
	  module :: atom(),
	  id :: pid(),
	  parent_interface = undefined %% For p2p/p2mp circuits
	 }).
-type isis_circuit() :: #isis_circuit{}.

-record (isis_name, {
	   system_id :: binary(),
	   name :: string()
	  }).
-type isis_name() :: #isis_name{}.

-type isis_crypto() :: none | {md5, binary()} | {text, string()}.
