%%%-------------------------------------------------------------------
%%% @author Rick Payne <rickp@rossfell.co.uk>
%%% @copyright (C) 2014, Rick Payne
%%% @doc
%%%
%%% @end
%%% Created :  10 March 2014 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------

-record (isis_address, {
	   afi :: atom(),
	   address :: integer(),
	   mask :: integer()
	  }).
-type isis_address() :: #isis_address{}.

-record (isis_interface, {
	   name :: string(),
	   mac :: binary(),
	   metric = 10 :: integer(),
	   enabled = false :: atom(),
	   pid :: pid(),
	   addresses = [] :: [isis_address()],
	   ifindex :: integer(),
	   mtu :: integer(),
	   mtu6 :: integer()
	  }).
-type isis_interface() :: #isis_interface{}.
