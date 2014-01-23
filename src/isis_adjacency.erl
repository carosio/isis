%%%-------------------------------------------------------------------
%%% @author Rick Payne <rickp@rossfell.co.uk>
%%% @copyright (C) 2014, Rick Payne
%%% @doc
%%%
%%% @end
%%% Created : 22 Jan 2014 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------
-module(isis_adjacency).

-behaviour(gen_fsm).

-include("isis_protocol.hrl").

%% API
-export([start_link/1]).

%% gen_fsm callbacks
-export([init/1,
	 new/2, init/2, up/2, down/2,
	 handle_event/3, handle_sync_event/4, handle_info/3,
	 terminate/3, code_change/4]).

-define(SERVER, ?MODULE).

-record(state, {
	  interface,     %% PID handling the interface
	  snpa,          %% Our SNPA
	  timer          %% Hold timer for this adjacency
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
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link(Args) ->
    gen_fsm:start_link({local, ?SERVER}, ?MODULE, Args, []).

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
%% @spec state_name(Event, State) ->
%%                   {next_state, NextStateName, NextState} |
%%                   {next_state, NextStateName, NextState, Timeout} |
%%                   {stop, Reason, NewState}
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
    {stop, stop, State}.

init({iih, IIH}, State) ->
    NextState = 
	case seen_ourselves(IIH, State) of
	    true -> up;
	    _ -> init
	end,
    NewState = start_timer(State),
    {next_state, NextState, NewState};
init({timeout}, State) ->
    {next_state, init, State};
init(stop, State) ->
    cancel_timer(State),
    {stop, stop, State}.

up({iih, IIH}, State) ->
    NewState =
	case seen_ourselves(IIH, State) of
	    true -> start_timer(State);
	    _ -> State
	end,
    {next_state, up, NewState};
up(stop, State) ->
    {stop, stop, State}.

down({iih, IIH}, State) ->
    {next_state, init, State};
down(stop, State) ->
    {stop, stop, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% There should be one instance of this function for each possible
%% state name. Whenever a gen_fsm receives an event sent using
%% gen_fsm:sync_send_event/[2,3], the instance of this function with
%% the same name as the current state name StateName is called to
%% handle the event.
%%
%% @spec state_name(Event, From, State) ->
%%                   {next_state, NextStateName, NextState} |
%%                   {next_state, NextStateName, NextState, Timeout} |
%%                   {reply, Reply, NextStateName, NextState} |
%%                   {reply, Reply, NextStateName, NextState, Timeout} |
%%                   {stop, Reason, NewState} |
%%                   {stop, Reason, Reply, NewState}
%% @end
%%--------------------------------------------------------------------
%% state_name(_Event, _From, State) ->
%%     Reply = ok,
%%     {reply, Reply, state_name, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Whenever a gen_fsm receives an event sent using
%% gen_fsm:send_all_state_event/2, this function is called to handle
%% the event.
%%
%% @spec handle_event(Event, StateName, State) ->
%%                   {next_state, NextStateName, NextState} |
%%                   {next_state, NextStateName, NextState, Timeout} |
%%                   {stop, Reason, NewState}
%% @end
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
terminate(_Reason, _StateName, _State) ->
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
parse_args([{snpa, Value} | T], State) ->
    parse_args(T, State#state{snpa = Value});
parse_args([{interface, Pid} | T], State) ->
    parse_args(T, State#state{interface = Pid});
parse_args([], State) ->
    State.

start_timer(State) ->
    cancel_timer(State),
    Timeout = isis_interface:get_state(State#state.interface,
				       hold_time),
    Timer = erlang:start_timer(Timeout * 1000, self(), trigger),
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
seen_ourselves(#isis_iih{tlv = TLVs}, State) ->
    R = lists:map(fun(A) -> seen_ourselves_tlv(A, State) end,
		  TLVs),
    length(R) > 0.

seen_ourselves_tlv(#isis_tlv_is_neighbors{neighbors = N}, State) ->
    lists:filter(fun(A) -> A =:= State#state.snpa end, N);
seen_ourselves_tlv(_, _) ->
    [].
