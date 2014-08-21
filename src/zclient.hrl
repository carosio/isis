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
