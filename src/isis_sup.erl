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
%%% Created :  2 Jan 2014 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------
-module(isis_sup).
-author('Rick Payne <rickp@rossfell.co.uk>').

-behaviour(supervisor).

%% API
-export([start_link/0, start_rib/0]).

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

start_rib() ->
    Restart = permanent,
    Shutdown = 2000,
    Type = worker,

    case application:get_env(isis, rib_client) of
	{ok, Client} ->
	    supervisor:start_child(
	      ?SERVER,
	      {Client, {Client, start_link, [[{type, isis}]]},
	       Restart, Shutdown, Type, [Client]}),
	    ok;
	Oops -> isis_logger:error("Got ~p for rib_client!", [Oops]),
		missing_rib_client
    end.

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

    %% Force GC to consider binaries touched by a process that hasn't
    %% died yet..
    erlang:system_flag(fullsweep_after, 100),

    %% We need crypto for MD5 anyway, so use it here...
    <<A:32,B:32,C:32>> = crypto:rand_bytes(12),
    random:seed({A, B, C}),

    RestartStrategy = one_for_one,
    MaxRestarts = 1000,
    MaxSecondsBetweenRestarts = 3600,

    SupFlags = {RestartStrategy, MaxRestarts, MaxSecondsBetweenRestarts},

    Restart = permanent,
    Shutdown = 2000,
    Type = worker,

    SPFSummary = {spf_summary, {spf_summary, start_link, []},
		  permanent, 10000, worker, []},
    WifiMetrics =
	case application:get_env(isis, wifi_metrics_server) of
	    {ok, _Server} ->
		[{isis_wifi, {isis_wifi, start_link, []},
		  Restart, Shutdown, Type, [isis_wifi]}];
	    _ -> []
	end,
    L1DB = {level1_lspdb, {isis_lspdb, start_link, [[{table, level_1}]]},
	    Restart, Shutdown, Type, [isis_lspdb]},
    L2DB = {level2_lspdb, {isis_lspdb, start_link, [[{table, level_2}]]},
	    Restart, Shutdown, Type, [isis_lspdb]},
    DBLog = {lspdb_log, {isis_lspdb_log, start_link, []},
	       Restart, Shutdown, Type, [isis_lspdb_log]},
    ConfigDB = {isis_config, {isis_config, start_link, []},
		Restart, Shutdown, Type, [isis_config]},
    ConfigPipe = {isis_config_pipe, {isis_config_pipe, start_link, []},
		  Restart, Shutdown, Type, [isis_config_pipe]},
    StartupParams =
	case application:get_env(isis, startup) of
	    undefined -> [];
	    {ok, Params} -> Params
	end,
    ISIS = {isis, {isis_system, start_link, [StartupParams]},
	    Restart, Shutdown, Type, [isis_system, isis_protocol, isis_enum]},
    ISISRib = {isis_rib, {isis_rib, start_link, []},
	       permanent, 10000, worker, []},
    ISISGenInfo = {isis_geninfo, {isis_geninfo, start_link, []},
		   permanent, 10000, worker, []},
    ISISConfig = {isis_netconf, {isis_netconf, start_link, []},
		  permanent, 1, worker, []},
    Webserver = {ybed_sup, {ybed_sup, start_link, []},
      		 permanent, 10000, supervisor, []},

    timer:apply_after(10000, application, start, [hostinfo]),

    {ok, {SupFlags,
	  WifiMetrics ++ 
	      [ISISConfig, SPFSummary, L1DB, L2DB, DBLog, ISIS, ISISRib,
	       ConfigDB, ConfigPipe,
	       ISISGenInfo
	      , Webserver %% , Demo
	      ]}}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
