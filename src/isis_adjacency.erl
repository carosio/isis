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
%%% Created : 22 Jan 2014 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------
-module(isis_adjacency).

-behaviour(gen_fsm).

-include("isis_system.hrl").
-include("isis_protocol.hrl").

%% API
-export([start_link/1, get_state/1, get_state/2]).

%% gen_fsm callbacks
-export([init/1,
	 new/2, init/2, up/2, down/2,
	 handle_event/3, handle_sync_event/4, handle_info/3,
	 terminate/3, code_change/4]).

-define(SERVER, ?MODULE).

-record(state, {
	  level,         %% Our 'level'
	  mode,          %% Are we broadcast, point_to_point or point_to_multipoint?
	  neighbor,      %% Neighbor's SNPA / IPv6 address (ie. whom we're adjacent with)
	  neighbor_id,   %% Neighbor ID
	  lan_id,        %% Who the negihbor believes is DIS
	  priority,      %% Priority it advertises
	  is_type,       %% Circuit Type as transmitted by the neighbor
	  metric,        %% Our metric for this interface
	  ip_addresses = [],  %% IP address of the neighbor
          ipv6_addresses = [], %% IPv6 address of the neighbor
	  interface,     %% PID handling the interface
	  interface_name,%% Name of our interface
	  level_pid,     %% PID handling the level
	  snpa,          %% Our SNPA
	  timer,         %% Hold timer for this adjacency
	  last_uptime    %% Time when we last changed to up
	 }).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Creates a gen_fsm process which calls Module:init/1 to
%% initialize. To ensure a synchronized start-up procedure, this
%% function does not return until Module:init/1 has returned.
%%
%% @spec start_link(list()) -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link(Args) ->
    %% gen_fsm:start_link(?MODULE, Args, []).
    gen_fsm:start(?MODULE, Args, []).

%%--------------------------------------------------------------------
%% @doc
%% Queries the adjacency fsm for specificic status information
%% @end
%%--------------------------------------------------------------------
get_state(Pid) ->
    {_, _, _, [_, _, _, _, Misc]} = sys:get_status(Pid),
    proplists:get_value("StateName", proplists:get_value(data, Misc)).

get_state(Pid, Field) ->
    gen_fsm:sync_send_all_state_event(Pid, {get, Field}).

%%%===================================================================
%%% gen_fsm callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Whenever a gen_fsm is started using gen_fsm:start/[3,4] or
%% gen_fsm:start_link/[3,4], this function is called by the new
%% process to initialize.
%%
%% @spec init(Args) -> {ok, StateName, State} |
%%                     {ok, StateName, State, Timeout} |
%%                     ignore |
%%                     {stop, StopReason}
%% @end
%%--------------------------------------------------------------------
init(Args) ->
    process_flag(trap_exit, true),
    State = parse_args(Args,
		       #state{timer = undef}),
    {ok, new, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% There should be one instance of this function for each possible
%% state name. Whenever a gen_fsm receives an event sent using
%% gen_fsm:send_event/2, the instance of this function with the same
%% name as the current state name StateName is called to handle
%% the event. It is also called if a timeout occurs.
%%
%% @end
%%--------------------------------------------------------------------
new({iih, _}, State) ->
    NewState = start_timer(State),
    {next_state, init, NewState};
new({timeout}, State) ->
    {next_state, down, State};
new({interface_down}, State) ->
    {next_state, down, State};
new(stop, State) ->
    cancel_timer(State),
    {stop, normal, State}.

init({iih, IIH}, State) ->
    {NextState, NewState} = 
	case seen_ourselves(IIH, State) of
	    true ->
		NS = State#state{
		       neighbor_id = IIH#isis_iih.source_id,
		       lan_id = IIH#isis_iih.dis,
		       priority = IIH#isis_iih.priority,
		       is_type = IIH#isis_iih.circuit_type,
		       last_uptime = isis_system:get_time()},
		update_adjacency(up, NS),
		{up, NS};
	    _ -> {init, State}
	end,
    NewState2 = start_timer(NewState),
    {next_state, NextState, NewState2};
init({timeout}, State) ->
    {next_state, init, State};
init(stop, State) ->
    cancel_timer(State),
    {stop, normal, State}.

up({iih, IIH}, State) ->
    NewState =
	case seen_ourselves(IIH, State) of
	    true -> start_timer(State);
	    _ -> State
	end,
    {NextState, NewState2} =
	verify_interface_addresses(IIH, NewState),
    {next_state, NextState, NewState2};
up({timeout}, State) ->
    isis_logger:debug("Timeout on adjacency with ~p", 
		      [State#state.neighbor_id]),
    NewState = start_timer(State),
    update_adjacency(down, State),
    isis_system:delete_all_sid_addresses(self()),
    {next_state, down, NewState#state{ip_addresses = [],
				      ipv6_addresses = []}};
up(stop, State) ->
    update_adjacency(down, State),
    isis_system:delete_all_sid_addresses(self()),
    {stop, normal, State#state{ip_addresses = [],
			       ipv6_addresses = []}}.

down({iih, IIH}, State) ->
    case seen_ourselves(IIH, State) of
	true ->
	    NewState = start_timer(State),
	    {next_state, init, NewState};
	_ ->
	    {next_state, down, State}
    end;
down({timeout}, State) ->
    cancel_timer(State),
    update_adjacency(down, State),
    {stop, normal, State};
down(stop, State) ->
    update_adjacency(down, State),
    {stop, normal, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% There should be one instance of this function for each possible
%% state name. Whenever a gen_fsm receives an event sent using
%% gen_fsm:sync_send_event/[2,3], the instance of this function with
%% the same name as the current state name StateName is called to
%% handle the event.
%%
%% @end
%%--------------------------------------------------------------------
%% state_name(_Event, _From, State) ->
%%     Reply = ok,
%%     {reply, Reply, state_name, State}.
%%--------------------------------------------------------------------
handle_event(_Event, StateName, State) ->
    {next_state, StateName, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Whenever a gen_fsm receives an event sent using
%% gen_fsm:sync_send_all_state_event/[2,3], this function is called
%% to handle the event.
%%
%% @spec handle_sync_event(Event, From, StateName, State) ->
%%                   {next_state, NextStateName, NextState} |
%%                   {next_state, NextStateName, NextState, Timeout} |
%%                   {reply, Reply, NextStateName, NextState} |
%%                   {reply, Reply, NextStateName, NextState, Timeout} |
%%                   {stop, Reason, NewState} |
%%                   {stop, Reason, Reply, NewState}
%% @end
%%--------------------------------------------------------------------
handle_sync_event({get, Field}, _From, StateName, State) ->
    Reply = get_state_reply(Field, State),
    {reply, Reply, StateName, State};
handle_sync_event(_Event, _From, StateName, State) ->
    Reply = ok,
    {reply, Reply, StateName, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_fsm when it receives any
%% message other than a synchronous or asynchronous event
%% (or a system message).
%%
%% @spec handle_info(Info,StateName,State)->
%%                   {next_state, NextStateName, NextState} |
%%                   {next_state, NextStateName, NextState, Timeout} |
%%                   {stop, Reason, NewState}
%% @end
%%--------------------------------------------------------------------
handle_info({timeout, _Ref, trigger}, StateName, State) ->
    cancel_timer(State),
    gen_fsm:send_event(self(), {timeout}),
    {next_state, StateName, State#state{timer = undef}}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_fsm when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_fsm terminates with
%% Reason. The return value is ignored.
%%
%% @spec terminate(Reason, StateName, State) -> void()
%% @end
%%--------------------------------------------------------------------
terminate(_Reason, _StateName, State) ->
    isis_logger:info("Adjacency with ~p ~p down due to timeout",
	       [State#state.neighbor, State#state.level]),
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, StateName, State, Extra) ->
%%                   {ok, StateName, NewState}
%% @end
%%--------------------------------------------------------------------
code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
parse_args([{mode, broadcast} | T], State) ->
    parse_args(T, State#state{mode = broadcast});
parse_args([{mode, point_to_multipoint} | T], State) ->
    parse_args(T, State#state{mode = point_to_multipoint});
parse_args([{neighbor, Value} | T], State) ->
    parse_args(T, State#state{neighbor = Value});
parse_args([{snpa, Value} | T], State) ->
    parse_args(T, State#state{snpa = Value});
parse_args([{interface, Pid, Name} | T], State) ->
    parse_args(T, State#state{interface = Pid,
			      interface_name = Name});
parse_args([{level_pid, Pid} | T], State) ->
    parse_args(T, State#state{level_pid = Pid});
parse_args([{level, level1_iih} | T], State) ->
    parse_args(T, State#state{level = level_1});
parse_args([{level, level2_iih} | T], State) ->
    parse_args(T, State#state{level = level_2});
parse_args([{metric, M} | T], State) ->
    parse_args(T, State#state{metric = M});
parse_args([], State) ->
    State.

get_state_reply(priority, #state{priority = P}) ->
    P;
get_state_reply(is_type, #state{is_type = T}) ->
    T;
get_state_reply(timer, #state{timer = Timer}) ->
    erlang:read_timer(Timer);
get_state_reply(last_uptime, #state{last_uptime = Last}) ->
    Last;
get_state_reply(_,_) ->
    unknown_field.

start_timer(State) ->
    cancel_timer(State),
    Timeout = isis_interface_level:get_state(State#state.level_pid,
					     hold_time),
    Timer = erlang:start_timer(Timeout, self(), trigger),
    State#state{timer = Timer}.

cancel_timer(State) ->
    case State#state.timer of
	undef -> undef;
	T -> erlang:cancel_timer(T)
    end.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Given an IIH, do we see ourselves listed in the is-neighbors TLV?
%%
%% @end
%%--------------------------------------------------------------------
seen_ourselves(#isis_iih{tlv = TLVs} = IIH, State) ->
    R = lists:filter(fun(A) -> seen_ourselves_tlv(A, State) end,
		  TLVs),
    isis_logger:debug("Seen ourselves in IIH from ~p: ~p",
		[case State#state.neighbor_id of
		     undefined ->
			 IIH#isis_iih.source_id;
		     N -> N
		 end, length(R) > 0]),
    length(R) > 0.

seen_ourselves_tlv(#isis_tlv_is_neighbors{neighbors = N}, State) ->
    length(lists:filter(fun(A) -> A =:= State#state.snpa end, N)) > 0;
seen_ourselves_tlv(_, _) ->
    false.

-spec update_adjacency(up | down, tuple()) -> atom().
update_adjacency(Direction, State) ->
    isis_interface_level:update_adjacency(State#state.level_pid,
					  Direction,
					  {State#state.neighbor_id,
					   State#state.neighbor,
					   State#state.priority}).

%% Ultimatley, this should verify that we share a subnet with the neighbor, or
%% we'll have no nexthops for routes!
verify_interface_addresses(IIH, #state{ip_addresses = IPAddresses,
				       ipv6_addresses = IPv6Addresses} = State) ->
    IfIndex = get_ifindex(State),
    Metric = State#state.metric,
    V4 = isis_protocol:filter_tlvs(isis_tlv_ip_interface_address, IIH#isis_iih.tlv),
    V4Addresses =
	lists:flatten(
	  lists:map(fun(#isis_tlv_ip_interface_address{addresses = A}) -> A end, V4)),
    V41 = sets:from_list(IPAddresses),
    V42 = sets:from_list(V4Addresses),
    V4Remove = lists:map(fun(F) -> {ipv4, {F, IfIndex, self()}} end, sets:to_list(sets:subtract(V41, V42))),
    V4Add = lists:map(fun(F) -> {ipv4, {F, IfIndex, self()}} end, sets:to_list(sets:subtract(V42, V41))),
    isis_system:add_sid_addresses(State#state.level, IIH#isis_iih.source_id, Metric, V4Add),
    isis_system:delete_sid_addresses(State#state.level, IIH#isis_iih.source_id, V4Remove),

    V6 = isis_protocol:filter_tlvs(isis_tlv_ipv6_interface_address, IIH#isis_iih.tlv),
    V6Addresses =
	lists:flatten(
	  lists:map(fun(#isis_tlv_ipv6_interface_address{addresses = A}) -> A end, V6)),
    V61 = sets:from_list(IPv6Addresses),
    V62 = sets:from_list(V6Addresses),
    V6Remove = lists:map(fun(F) -> {ipv6, {F, IfIndex, self()}} end, sets:to_list(sets:subtract(V61, V62))),
    V6Add = lists:map(fun(F) -> {ipv6, {F, IfIndex, self()}} end, sets:to_list(sets:subtract(V62, V61))),
    isis_system:add_sid_addresses(State#state.level, IIH#isis_iih.source_id, Metric, V6Add),
    isis_system:delete_sid_addresses(State#state.level, IIH#isis_iih.source_id, V6Remove),
    {up, State#state{ip_addresses = V4Addresses,
		     ipv6_addresses = V6Addresses}}.

get_ifindex(#state{interface_name = Name}) ->
    I = isis_system:get_interface(Name),
    I#isis_interface.ifindex.
