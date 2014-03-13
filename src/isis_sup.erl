%%%-------------------------------------------------------------------
%%% @author Rick Payne <rickp@rossfell.co.uk>
%%% @copyright (C) 2014, Rick Payne
%%% @doc
%%%
%%% @end
%%% Created :  2 Jan 2014 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------
-module(isis_sup).
-author('Rick Payne <rickp@rossfell.co.uk>').

-behaviour(supervisor).

%% API
-export([start_link/0]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).

%%%===================================================================
%%% API functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the supervisor
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%%%===================================================================
%%% Supervisor callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Whenever a supervisor is started using supervisor:start_link/[2,3],
%% this function is called by the new process to find out about
%% restart strategy, maximum restart frequency and child
%% specifications.
%%
%% @spec init(Args) -> {ok, {SupFlags, [ChildSpec]}} |
%%                     ignore |
%%                     {error, Reason}
%% @end
%%--------------------------------------------------------------------
init([]) ->
    RestartStrategy = one_for_one,
    MaxRestarts = 1000,
    MaxSecondsBetweenRestarts = 3600,

    SupFlags = {RestartStrategy, MaxRestarts, MaxSecondsBetweenRestarts},

    Restart = permanent,
    Shutdown = 2000,
    Type = worker,

    ZChild = {zclient, {zclient, start_link, [[{type, isis}]]},
     	      Restart, Shutdown, Type, [zclient]},
    L1DB = {level1_lspdb, {isis_lspdb, start_link, [[{table, level_1}]]},
	    Restart, Shutdown, Type, [isis_lspdb]},
    L2DB = {level2_lspdb, {isis_lspdb, start_link, [[{table, level_2}]]},
	    Restart, Shutdown, Type, [isis_lspdb]},
    %% Move the system-id and area into the app config at somepoint...
    ISIS = {isis, {isis_system, start_link, [[{system_id, <<255,255,0,0,3,3>>},
					      {areas, [<<73, 0, 2>>]}]]},
	    Restart, Shutdown, Type, [isis_system, isis_protocol, isis_enum]},
    {ok, {SupFlags, [ZChild, L1DB, L2DB, ISIS]}}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
