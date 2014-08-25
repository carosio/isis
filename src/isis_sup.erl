%%%-------------------------------------------------------------------
%%% @author Rick Payne <rickp@rossfell.co.uk>
%%% @copyright (C) 2014, Alistair Woodman, California USA <awoodman@netdef.org>
%%% @doc
%%%
%%% This file is part of AutoISIS.
%%%
%%% License:
%%% AutoISIS can be used (at your option) under the following GPL or under
%%% a commercial license
%%% 
%%% Choice 1: GPL License
%%% AutoISIS is free software; you can redistribute it and/or modify it
%%% under the terms of the GNU General Public License as published by the
%%% Free Software Foundation; either version 2, or (at your option) any
%%% later version.
%%% 
%%% AutoISIS is distributed in the hope that it will be useful, but
%%% WITHOUT ANY WARRANTY; without even the implied warranty of
%%% MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See 
%%% the GNU General Public License for more details.
%%% 
%%% You should have received a copy of the GNU General Public License
%%% along with GNU Zebra; see the file COPYING.  If not, write to the Free
%%% Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
%%% 02111-1307, USA.
%%% 
%%% Choice 2: Commercial License Usage
%%% Licensees holding a valid commercial AutoISIS may use this file in 
%%% accordance with the commercial license agreement provided with the 
%%% Software or, alternatively, in accordance with the terms contained in 
%%% a written agreement between you and the Copyright Holder.  For
%%% licensing terms and conditions please contact us at 
%%% licensing@netdef.org
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
    RibChild = 
	case application:get_env(isis, rib_client) of
	    {ok, Client} -> {Client, {Client, start_link, [[{type, isis}]]},
			     Restart, Shutdown, Type, [Client]};
	    Oops -> lager:error("Got ~p for rib_client!", [Oops]),
		    missing_rib_client
	end,
    L1DB = {level1_lspdb, {isis_lspdb, start_link, [[{table, level_1}]]},
	    Restart, Shutdown, Type, [isis_lspdb]},
    L2DB = {level2_lspdb, {isis_lspdb, start_link, [[{table, level_2}]]},
	    Restart, Shutdown, Type, [isis_lspdb]},
    StartupParams =
	case application:get_env(isis, startup) of
	    undefined -> [];
	    {ok, Params} -> Params
	end,
    ISIS = {isis, {isis_system, start_link, [StartupParams]},
	    Restart, Shutdown, Type, [isis_system, isis_protocol, isis_enum]},
    ISISRib = {isis_rib, {isis_rib, start_link, []},
	       permanent, 10000, worker, []},
    %% Demo = {demo, {demo, start_link, []},
    %%  	    permanent, 1000, worker, []},
    Webserver = {ybed_sup, {ybed_sup, start_link, []},
      		 permanent, 10000, supervisor, []},
    {ok, {SupFlags, [SPFSummary, RibChild, L1DB, L2DB, ISIS, ISISRib
		    , Webserver %% , Demo
		    ]}}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
