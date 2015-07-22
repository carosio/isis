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
%%% Created : 18 Jan 2014 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------
-module(isis_interface).

-behaviour(gen_server).

-include("isis_system.hrl").
-include("isis_protocol.hrl").

-define(BINARY_LIMIT, 5 * 1024 * 1024).    %% GC after 5MB of binarys have accumulated..

%% API
-export([start_link/1, stop/1,
	 get_state/3, get_state/1, set/2,
	 enable_level/2, disable_level/2, levels/1, get_level_pid/2,
	 clear_neighbors/1, clear_neighbors/2,
	 dump_config/1,
	 send_pdu/5, received_pdu/3,
	 update_metric/3
	]).

%% Debug export
-export([]).
-compile(export_all).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE).
-define(ETH_P_802_2, 16#0004).

-record(state, {
	  name,            %% Interface name
	  interface_mod,   %% Module handling I/F I/O
	  interface_pid,   %% Interface I/O Pid
	  mode = broadcast,%% broadcast or point-to-multipoint
	  pseudo_interfaces, %% Map 'From' to pseudo interface for point-to-(multi)point modes
	  level1,          %% Pid handling the levels
	  level2
	 }).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @spec start_link(list()) -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link(Args) ->
    gen_server:start_link(?MODULE, Args, []).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================
send_pdu(Pid, Type, Packet, Packet_Size, Level) ->
    gen_server:cast(Pid, {send_pdu, Type, Packet, Packet_Size, Level}).

received_pdu(Pid, From, PDU) ->
    gen_server:cast(Pid, {received_pdu, From, PDU}).

stop(Pid) ->
    gen_server:cast(Pid, stop).

get_state(Pid, Level, Item) ->
    gen_server:call(Pid, {get_state, Level, Item}).

get_state(Pid, Item) ->
    gen_server:call(Pid, {get_state, Item}).

get_state(Pid) ->
    gen_server:call(Pid, {get_state}).

set(Pid, Values) ->
    gen_server:call(Pid, {set, Values}).

get_level_pid(undefined, _) ->
    not_enabled;
get_level_pid(Pid, Level) ->
    gen_server:call(Pid, {get_level_pid, Level}).

get_level(Pid, Level, Value) ->
    gen_server:call(Pid, {get, Level, Value}).

enable_level(Pid, Level) ->
    gen_server:call(Pid, {enable, Level}).

disable_level(Pid, Level) ->
    gen_server:call(Pid, {disable, Level}).

levels(Pid) ->
    gen_server:call(Pid, {levels}).

clear_neighbors(Pid) ->
    gen_server:cast(Pid, {clear_neighbors, all}).

clear_neighbors(Pid, Adjs) ->
    gen_server:cast(Pid, {clear_neighbors, Adjs}).

dump_config(Pid) ->
    gen_server:call(Pid, {dump_config}).

update_metric(Pid, Key, Metric) ->
    gen_server:call(Pid, {update_metric, Key, Metric}).

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
init(Args) ->
    process_flag(trap_exit, true),
    State = extract_args(Args, #state{level1 = undef,
				      level2 = undef,
				      pseudo_interfaces = dict:new()}),
    IFModule = State#state.interface_mod,
    case IFModule:start_link([{name, State#state.name},
			      {interface_pid, self()},
			      {mode, State#state.mode}]) of
	{ok, Pid} ->
	    erlang:send_after(60 * 1000, self(), {gc}),
	    {ok, State#state{interface_pid = Pid}};
	error ->
	    {stop, no_socket}
    end.

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
handle_call({get_state, level_1, Item}, _From,
	    #state{level1 = L1Pid} = State) when is_pid(L1Pid) ->
    {reply, isis_interface_level:get_state(L1Pid, Item), State};
handle_call({get_state, level_2, Item}, _From,
	    #state{level2 = L2Pid} = State) when is_pid(L2Pid) ->
    {reply, isis_interface_level:get_state(L2Pid, Item), State};
handle_call({get_state, _, _}, _From, State) ->
    {reply, level_not_configured, State};

handle_call({get_state, pseudo_interfaces}, _From, State) ->
    {reply, State#state.pseudo_interfaces, State};

handle_call({get_state}, _From, State) ->
    {reply, State, State};

handle_call({enable, Level}, _From, State)  ->
    io:format("Enabling level ~p~n", [Level]),
    handle_enable_level(Level, State);

handle_call({disable, Level}, _From, State) ->
    handle_disable_level(Level, State);

handle_call({levels}, _From, State) ->
    Levels = 
	case {State#state.level1, State#state.level2} of
	    {undef, undef} -> [];
	    {_, undef} -> [level_2];
	    {undef, _} -> [level_1];
	    {_, _} -> [level_1, level_2]
	end,
    {reply, Levels, State};

handle_call({get_level_pid, level_1}, _From,
	    #state{level1 = L1Pid} = State) when is_pid(L1Pid) ->
    {reply, L1Pid, State};
handle_call({get_level_pid, level_2}, _From,
	    #state{level2 = L2Pid} = State) when is_pid(L2Pid) ->
    {reply, L2Pid, State};
handle_call({get_level_pid, _}, _From, State) ->
    {reply, not_enabled, State};

handle_call({dump_config}, _From, State) ->
    dump_config_state(State),
    {reply, ok, State};

handle_call({get, level_1, Value}, _From, State) ->
    R = isis_interface_level:get_state(State#state.level1, Value),
    {reply, R, State};
handle_call({get, level_2, Value}, _From, State) ->
    R = isis_interface_level:get_state(State#state.level2, Value),
    {reply, R, State};

handle_call({update_metric, Key, Metric}, _from, State)
  when is_binary(Key) ->
    %% Adjacency update
    isis_interface_level:update_metric(State#state.level1, Key, Metric),
    isis_interface_level:update_metric(State#state.level2, Key, Metric),
    {reply, ok, State};
handle_call({update_metric, Key, Metric}, _From, State) ->
    isis_logger:error("Updating interface metric for p2mp... ~p ~p",
		     [Key, dict:to_list(State#state.pseudo_interfaces)]),
    Result = 
	case dict:find({ipv6, Key}, State#state.pseudo_interfaces) of
	    {ok, P} ->
		isis_interface_p2mp:update_metric(P),
		ok;
	    error ->
		not_found
	end,
    {reply, Result, State};

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
handle_cast({send_pdu, iih, PDU, PDU_Size, Level}, State) ->
    send_packet(PDU, PDU_Size, Level, State),
    {noreply, State};
handle_cast({send_pdu, _Type, PDU, PDU_Size, level_1},
	    #state{level1 = P} = State) when is_pid(P) ->
    Adj = isis_interface_level:get_state(P, up_adjacencies),
    case length(dict:fetch_keys(Adj)) of
	0 -> no_adj;
	_ -> send_packet(PDU, PDU_Size, level_1, State)
    end,
    {noreply, State};
handle_cast({send_pdu, _Type, PDU, PDU_Size, level_2},
	    #state{level2 = P} = State) when is_pid(P) ->
    Adj = isis_interface_level:get_state(P, up_adjacencies),
    case length(dict:fetch_keys(Adj)) of
	0 -> no_adj;
	_ -> send_packet(PDU, PDU_Size, level_2, State)
    end,
    {noreply, State};
handle_cast({send_pdu, _PDU, _PDU_Size, _}, State) ->
    {noreply, State};

handle_cast(stop, #state{interface_mod = Mod,
			 interface_pid = Pid,
			 level1 = Level1,
			 level2 = Level2} = State) ->
    %% Close down the port (does this close the socket?)
    Mod:stop(Pid),

    %% Notify our adjacencies
    case is_pid(Level1) of
	true -> gen_server:cast(Level1, stop);
	_ -> no_process
    end,
    case is_pid(Level2) of
	true -> gen_server:cast(Level2, stop);
	_ -> no_process
    end,
    {stop, normal, State};

handle_cast({set, level_1, Values}, #state{level1 = P} = State)
  when is_pid(P) ->
    isis_interface_level:set(P, Values),
    {noreply, State};
handle_cast({set, level_2, Values}, #state{level2 = P} = State)
  when is_pid(P) ->
    isis_interface_level:set(P, Values),
    {noreply,  State};
handle_cast({set, _, _}, State) ->
    {noreply, State};

handle_cast({clear_neighbors, Which}, #state{
				 level1 = Level1,
				 level2 = Level2} = State) ->
    case is_pid(Level1) of
	true -> isis_interface_level:clear_neighbors(Level1, Which);
	_ -> no_level
    end,
    case is_pid(Level2) of
	true -> isis_interface_level:clear_neighbors(Level2, Which);
	_ -> no_level
    end,
    {noreply, State};
handle_cast({received_pdu, From, PDU}, #state{mode = broadcast} = State) ->
    handle_pdu(From, PDU, State),
    {noreply, State};
handle_cast({received_pdu, From, PDU}, #state{mode = point_to_multipoint} = State) ->
    {noreply, handle_p2mp_pdu(From, PDU, State)};

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
handle_info({_port, {data, _}}, State) ->
    {noreply, State};

handle_info({gc}, State) ->
    case erlang:memory(binary) of
	Binary when Binary > ?BINARY_LIMIT ->
	    isis_logger:debug("Forcing garbage collection..."),
	    erlang:garbage_collect(self());
	_ ->
	    ok
    end,
    erlang:send_after(60 * 1000, self(), {gc}),
    {noreply, State};

handle_info({'EXIT', Pid, normal}, State)
  when Pid =:= State#state.level1 ->
    {noreply, State#state{level1 = undef}};
handle_info({'EXIT', Pid, normal}, State)
  when Pid =:= State#state.level2 ->
    {noreply, State#state{level2 = undef}};
handle_info({'EXIT', Pid, normal}, State) ->
    %% Check to see if its one of our p2mp processes
    NewPI =
	dict:filter(fun(_From, P) when P =:= Pid -> false;
		       (_, _) -> true
		    end, State#state.pseudo_interfaces),
    {noreply, State#state{pseudo_interfaces = NewPI}};

handle_info(Info, State) ->
    isis_logger:debug("Unknown message: ~p", [Info]),
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
%%--------------------------------------------------------------------
%% @private
%% @doc
%% 
%% Handle the various PDUs that we can receive on this interface
%%
%% @end
%%--------------------------------------------------------------------
handle_pdu(From, #isis_iih{pdu_type = level1_iih} = PDU, #state{level1 = Pid})
  when is_pid(Pid) ->
    isis_interface_level:handle_pdu(Pid, From, PDU);
handle_pdu(From, #isis_iih{pdu_type = level2_iih} = PDU, #state{level2 = Pid})
  when is_pid(Pid) ->
    isis_interface_level:handle_pdu(Pid, From, PDU);
handle_pdu(From, #isis_lsp{pdu_type = level1_lsp} = PDU, #state{level1 = Pid})
  when is_pid(Pid) ->
    isis_interface_level:handle_pdu(Pid, From, PDU);
handle_pdu(From, #isis_lsp{pdu_type = level2_lsp} = PDU, #state{level2 = Pid})
  when is_pid(Pid) ->
    isis_interface_level:handle_pdu(Pid, From, PDU);
handle_pdu(From, #isis_csnp{pdu_type = level1_csnp} = PDU, #state{level1 = Pid})
  when is_pid(Pid) ->
    isis_interface_level:handle_pdu(Pid, From, PDU);
handle_pdu(From, #isis_csnp{pdu_type = level2_csnp} = PDU, #state{level2 = Pid})
  when is_pid(Pid) ->
    isis_interface_level:handle_pdu(Pid, From, PDU);
handle_pdu(From, #isis_psnp{pdu_type = level1_psnp} = PDU, #state{level1 = Pid})
  when is_pid(Pid) ->
    isis_interface_level:handle_pdu(Pid, From, PDU);
handle_pdu(From, #isis_psnp{pdu_type = level2_psnp} = PDU, #state{level2 = Pid})
  when is_pid(Pid) ->
    isis_interface_level:handle_pdu(Pid, From, PDU);
handle_pdu(_From, _Pdu, State) ->
    State.

%% Handle P2MP message
handle_p2mp_pdu(From, PDU, #state{pseudo_interfaces = PI} = State) ->
    %% Map 'From' into a 'virtual circuit'
    {Pid, NextState} = 
	case dict:find(From, PI) of
	    {ok, P} -> {P, State};
	    error ->
		{ok, P} = isis_interface_p2mp:start_link([{from, From},
							  {interface_name, State#state.name, self()},
							  {interface_module, State#state.interface_mod},
							  {interface_pid, State#state.interface_pid}]),
		erlang:monitor(process, P),
		{P, State#state{pseudo_interfaces = dict:store(From, P, PI)}}
	end,
    %% Send PDU to the interface...
    isis_interface_p2mp:handle_pdu(Pid, PDU),
    NextState.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% 
%% Turn on a level
%%
%% @end
%%--------------------------------------------------------------------
handle_enable_level(level_1, #state{level1 = Level_1} = State) ->
    Level = 
	case is_pid(Level_1) of
	    false ->
		Mtu = get_mtu(State),
		Mac = get_mac(State),
		{ok, Pid} = isis_interface_level:start_link([{level, level_1},
							     {snpa, Mac},
							     {interface, State#state.name, self(),
							      Mtu},
							     {mode, State#state.mode}]),
		isis_logger:debug("Interface level: ~p ~p ~p ~p", [State#state.name, Mtu, Mac, Pid]),
		Pid;
	    _ -> Level_1
	end,
    {reply, ok, State#state{level1 = Level}};
handle_enable_level(level_2, #state{level2 = Level_2} = State) ->
    Level = 
	case is_pid(Level_2) of
	    false ->
		Mtu = get_mtu(State),
		Mac = get_mac(State),
		{ok, Pid} = isis_interface_level:start_link([{level, level_2},
							     {snpa, Mac},
							     {interface, State#state.name, self(),
							      Mtu}]),
		Pid;
	    _ -> Level_2
	end,
    {reply, ok, State#state{level2 = Level}};
handle_enable_level(_, State) ->
    {reply, invalid_level, State}.

handle_disable_level(level_1, #state{level1 = Level_1} = State) when is_pid(Level_1) ->
    isis_interface_level:stop(Level_1),
    {reply, ok, State#state{level1 = undef}};
handle_disable_level(level_2, #state{level2 = Level_2} = State) when is_pid(Level_2) ->
    isis_interface_level:stop(Level_2),
    {reply, ok, State#state{level2 = undef}};
handle_disable_level(_, State) ->
    {reply, invalid_level, State}.


%%--------------------------------------------------------------------
%% @private
%% @doc
%%
%%
%%
%% @end
%%--------------------------------------------------------------------
-spec htons(integer()) -> integer().
htons(I) ->
	<<HI:16/native>> = <<I:16>>,
	HI.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% 
%%
%%
%% @end
%%--------------------------------------------------------------------
send_packet(Pdu, Pdu_Size, Level, State) ->
    (State#state.interface_mod):send_pdu(State#state.interface_pid, Pdu, Pdu_Size, Level).


get_mac(#state{interface_mod = Mod, interface_pid = Pid}) ->
    Mod:get_mac(Pid).

get_mtu(#state{interface_mod = Mod, interface_pid = Pid}) ->
    Mod:get_mtu(Pid).

extract_args([{name, Name} | T], State) ->
    extract_args(T, State#state{name = Name});
extract_args([{interface_module, ModName} | T], State) ->
    extract_args(T, State#state{interface_mod = ModName});
extract_args([{mode, broadcast} | T], State) ->
    extract_args(T, State#state{mode = broadcast});
extract_args([{mode, point_to_multipoint} | T], State) ->
    extract_args(T, State#state{mode = point_to_multipoint});
extract_args([], State) ->
    State.

dump_config_fields([{level1, P} | Fs], #state{name = N} = State)
  when is_pid(P) ->
    io:format("isis_system:enable_level(\"~s\", level_1).~n", [N]),
    isis_interface_level:dump_config(N, level_1, P),
    dump_config_fields(Fs, State);
dump_config_fields([{level2, P} | Fs], #state{name = N} = State)
  when is_pid(P) ->
    io:format("isis_system:enable_level(\"~s\", level_2).~n", [N]),
    isis_interface_level:dump_config(N, level_2, P),
    dump_config_fields(Fs, State);
dump_config_fields([_ | Fs], State) ->
    dump_config_fields(Fs, State);
dump_config_fields([], _) ->
    ok.

dump_config_state(State) ->
    S = lists:zip(record_info(fields, state),
		  tl(erlang:tuple_to_list(State))),
    dump_config_fields(S, State).
