%%%-------------------------------------------------------------------
%%% @author Rick Payne <rickp@rossfell.co.uk>
%%% @copyright (C) 2014, Rick Payne
%%% @doc
%%%
%%% Provide some commands to interact with the running erlang isisd,
%%% pending integration with some other CLI system (yang)
%%%
%%% @end
%%% Created : 12 Apr 2014 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------
-module(isis_cli).

%% API
-export([
	%% Database examination
	show_database/0, show_database/1]).

%%%===================================================================
%%% API
%%%===================================================================
show_database() ->
    do_show_database(level1),
    do_show_database(level2).
show_database(Level) ->
    do_show_database(Level).

%%--------------------------------------------------------------------
%% @doc
%% @spec
%% @end
%%--------------------------------------------------------------------

%%%===================================================================
%%% Internal functions
%%%===================================================================
do_show_database(Level) ->
    ok.
