%%%-------------------------------------------------------------------
%%% @author Rick Payne <rickp@rossfell.co.uk>
%%% @copyright (C) 2014, Alistair Woodman, California USA <awoodman@netdef.org>
%%% @doc
%%%
%%% @end
%%% Created :  2 Jan 2014 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------

-define (ZEBRA_HEADER_MARKER, 255).
-define (ZEBRA_HEADER_SIZE, 6).
-define (ZSERV_VERSION, 2).

-define (ZEBRA_AFI_IPV4, 2).
-define (ZEBRA_AFI_IPV6, 10).

%%%===================================================================
%%% Messages
%%%===================================================================
-record (zclient_header, {
	   command :: atom(),
	   length :: integer()
	  }).
-type zclient_header() :: #zclient_header{}.

%%%===================================================================
%%% Structures built from those messages
%%%===================================================================
-record (zclient_prefix, {
	   afi :: atom(),
	   address :: integer(),
	   mask_length :: integer(),
	   flags :: integer()
	  }).
-type zclient_prefix() :: #zclient_prefix{}.

-record (zclient_route_key, {
	   prefix :: zclient_prefix,
	   source = undefined :: zclient_prefix() | undefined
	  }).
-type zclient_route_key() :: #zclient_route_key{}.

-record (zclient_route, {
	   route :: zclient_route_key(),
	   nexthops = [] :: [integer()],
	   ifindexes = [] :: [integer()],
	   metric :: integer()
	  }).
-type zclient_route() :: #zclient_route{}.
	   
-record (zclient_interface, {
	   name :: string(),
	   ifindex :: integer(),
	   status :: integer(),
	   flags :: integer(),
	   metric :: integer(),
	   mtu :: integer(),
	   mtu6 :: integer(),
	   bandwidth :: integer(),
	   mac :: binary(),
	   addresses = [] :: [zclient_prefix()]
	  }).
-type zclient_interface() :: #zclient_interface{}.

