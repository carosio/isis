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
%%% Created : 20 Jul 2015 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------
-module(isis_wifi).
-author('Rick Payne <rickp@rossfell.co.uk>').

-behaviour(gen_server).

-include("isis_system.hrl").

%% API
-export([start_link/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE).

-record(state, {
	  socket,
	  buffer = [],
	  reconnect_timer = undefined
	 }).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link() ->
    gen_server:start_link(?MODULE, [], []).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%%
%% @spec init(Args) -> {ok, State} |
%%                     {ok, State, Timeout} |
%%                     ignore |
%%                     {stop, Reason}
%% @end
%%--------------------------------------------------------------------
init([]) ->
    S = connect(),
    {ok, #state{socket = S}}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling call messages
%%
%% @spec handle_call(Request, From, State) ->
%%                                   {reply, Reply, State} |
%%                                   {reply, Reply, State, Timeout} |
%%                                   {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, Reply, State} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling cast messages
%%
%% @spec handle_cast(Msg, State) -> {noreply, State} |
%%                                  {noreply, State, Timeout} |
%%                                  {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_cast(_Msg, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling all non call/cast messages
%%
%% @spec handle_info(Info, State) -> {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_info({tcp, _Socket, Data}, State) ->
    %% Parse message or buffer..
    Buffer = State#state.buffer ++ Data,
    NewState = parse_buffer(State#state{buffer = Buffer}),
    {noreply, NewState};
handle_info({tcp_closed, _Socket}, State) ->
    NewState = reconnect(State),
    {noreply, NewState};
handle_info({tcp_error, _Socket, Reason}, State) ->
    isis_logger:error("Wifi socket closed because of ~p", [Reason]),
    NewState = reconnect(State),
    {noreply, NewState};
handle_info({timeout, _Ref, reconnect}, State) ->
    NewState = reconnect(State),
    {noreply, NewState};
handle_info(_Info, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_server terminates
%% with Reason. The return value is ignored.
%%
%% @spec terminate(Reason, State) -> void()
%% @end
%%--------------------------------------------------------------------
terminate(_Reason, _State) ->
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, State, Extra) -> {ok, NewState}
%% @end
%%--------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
connect() ->
    {ok, Address} = application:get_env(isis, wifi_metrics_server),
    {ok, Port} = application:get_env(isis, wifi_metrics_port),
    gen_tcp:connect(Address, Port, []).

reconnect(State) ->
    case connect() of
	{ok, S} -> State#state{socket = S};
	{error, _} ->
	    Timer = erlang:start_timer(5000, self(), reconnect),
	    State#state{reconnect_timer = Timer}
    end.

parse_buffer(#state{buffer = B} = State) ->
    Lines = string:tokens(B, [$\r, $\n]),
    Remaining = 
	lists:filtermap(
	  fun(Line) ->
		  Statements = string:tokens(Line, [$,]),
		  case length(Statements) of
		      4 ->
			  apply_metrics(Statements),
			  false;
		      _ -> {true, Line}
		  end
	  end, Lines),
    NewBuffer = lists:foldl(fun(L, A) -> A ++ " " ++ L end, "", Remaining),
    State#state{buffer = NewBuffer}.

apply_metrics([Interface, Mac, V6Address, MetricAsc]) ->
    {Metric, []} = string:to_integer(MetricAsc),
    case isis_system:get_interface(Interface) of
	unknown ->
	    ok;
	#isis_interface{} = I ->
	    case parse_mac(Mac) of
		error -> ok;
		MacAddr ->
		    isis_logger:error("Setting adjacency ~p on interface ~p to metric ~p",
				      [MacAddr, I#isis_interface.name, Metric]),
		    isis_interface:update_metric(I#isis_interface.pid, MacAddr, Metric)
	    end,
	    case inet:parse_address(V6Address) of
		{ok, Addr} ->
		    isis_config:set([{interface, I#isis_interface.name},
				     {level, level_1},
				     {neighbor, {ipv6, Addr}}], {metric, Metric}),
		    isis_interface:update_metric(I#isis_interface.pid, Addr, Metric);
		{error, _} ->
		    ok
	    end
    end.

parse_mac(Mac) ->
    {ok, Bytes, []} = io_lib:fread("~16u:~16u:~16u:~16u:~16u:~16u", Mac),
    << <<X:8>> || X <- Bytes >>.

