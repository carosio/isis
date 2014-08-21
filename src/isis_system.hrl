%%%-------------------------------------------------------------------
%%% @author Rick Payne <rickp@rossfell.co.uk>
%%% @copyright (C) 2014, Alistair Woodman, California USA <awoodman@netdef.org>
%%% @doc
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

-record (isis_name, {
	   system_id :: binary(),
	   name :: string()
	  }).
-type isis_name() :: #isis_name{}.
