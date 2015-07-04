%%%-------------------------------------------------------------------
%%% @author Rick Payne <rickp@rossfell.co.uk>
%%% @copyright (C) 2014, Alistair Woodman, California USA <awoodman@netdef.org>
%%% @doc
%%%
%%% Handle an IS-IS level for a given interface.
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
%%% Created :  7 Feb 2014 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------
-module(isis_interface_level).

-behaviour(gen_server).

-include("isis_system.hrl").
-include("isis_protocol.hrl").
-include("isis_interface_lib.hrl").

%% API
-export([start_link/1, get_state/1, get_state/2, set/2,
	 update_adjacency/3, clear_neighbors/2,
	 dump_config/3,
	 send_pdu/5]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3,
	 handle_pdu/3, stop/1]).

-define(SERVER, ?MODULE).

-record(state, {
	  level,           %% The level
	  interface_ref,   %% Interface
	  interface_name,
	  mode = broadcast,%% Mode is either broadcast, point_to_point or point_to_multipoint
	  system_id,       %% Cached system_id
	  snpa,            %% Our mac address
	  mtu,
	  database = undef, %% The LSPDB reference
	  hello_interval = (?DEFAULT_HOLD_TIME / 3),
	  hold_time = ?DEFAULT_HOLD_TIME,
	  csnp_timer = undef,
	  metric = ?DEFAULT_METRIC,
	  metric_type = wide :: wide | narrow,
	  padding = true :: true | false,  %% To pad or not...
	  iih_timer = undef :: reference() | undef, %% iih timer for this level
	  adj_handlers,     %% Dict for SNPA -> FSM pid
	  up_adjacencies,  %% Dict for Pid -> SID (populated by adj fsm when adj is up)
	  priority = 64,   %% 0 - 127 (6 bit) for our priority, highest wins
	  dis = undef,     %% Current DIS for this interface ( 7 bytes, S-id + pseudonode)
	  dis_priority,    %% Current DIS's priority
	  are_we_dis = false,  %% True if we're the DIS
	  pseudonode = 0,  %% Allocated pseudonode if we're DIS
	  dis_timer = undef :: reference() | undef, %% If we're DIS, we use this timer to announce CSNPs
	  pdu_state = #isis_pdu_state{}
	 }).

%%%===================================================================
%%% API
%%%===================================================================
handle_pdu(Pid, From, PDU) ->
    gen_server:cast(Pid, {received, From, PDU}).

send_pdu(Pid, Type, PDU, PDU_Size, Level) ->
    gen_server:cast(Pid, {send_pdu, Type, PDU, PDU_Size, Level}).

get_state(Pid) ->
    gen_server:call(Pid, {get_state}).

get_state(Pid, Item) ->
    gen_server:call(Pid, {get_state, Item}).

set(Pid, Values) ->
    gen_server:cast(Pid, {set, Values}).

update_adjacency(Pid, Direction, {Neighbor, Mac, Priority}) ->
    gen_server:cast(Pid, {update_adjacency, Direction, self(), {Neighbor, Mac, Priority}}).

clear_neighbors(Pid, Which) ->
    gen_server:call(Pid, {clear_neighbors, Which}).

dump_config(Name, Level, Pid) ->
    gen_server:call(Pid, {dump_config, Name, Level}).

stop(Pid) ->
    gen_server:cast(Pid, stop).

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link(Args) ->
    gen_server:start_link(?MODULE, Args, []).

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
init(Args) ->
    process_flag(trap_exit, true),
    State = parse_args(Args, #state{
				adj_handlers = dict:new(),
				up_adjacencies = dict:new()
			       }),
    gen_server:cast(self(), {set_database}),
    {ok, State}.

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
handle_call({send_iih}, _From, State) ->
    try send_iih(State) of 
	_ -> {reply, ok, State}
    catch
	bad_enum -> 
	    isis_logger:error("Failed in send_iih"),
	    {reply, ok, State}
    end;
handle_call({get_state}, _From, State) ->
    {reply, State, State};

handle_call({get_state, hello_interval}, _From, State) ->
    {reply, State#state.hello_interval, State};
handle_call({get_state, hold_time}, _From, State) ->
    {reply, State#state.hold_time, State};
handle_call({get_state, metric}, _From, State) ->
    {reply, State#state.metric, State};
handle_call({get_state, adjacencies}, _From, State) ->
    {reply, State#state.adj_handlers, State};
handle_call({get_state, up_adjacencies}, _From, State) ->
    {reply, State#state.up_adjacencies, State};
handle_call({get_state, priority}, _From, State) ->
    {reply, State#state.priority, State};
handle_call({get_state, csnp_interval}, _From, State) ->
    {reply, State#state.csnp_timer, State};
handle_call({get_state, authentication}, _From,
	    #state{pdu_state = Pdu} = State) ->
    {reply, Pdu#isis_pdu_state.authentication, State};
handle_call({get_state, level_authentication}, _From,
	    #state{pdu_state = Pdu} = State) ->
    {reply, Pdu#isis_pdu_state.level_authentication, State};
handle_call({get_state, pseudonode}, _From, State) ->
    {reply, State#state.pseudonode, State};

handle_call({clear_neighbors, all}, _From, State) ->
    dict:map(fun(_, {_, Pid}) ->
		     gen_fsm:send_event(Pid, stop)
	     end,
	     State#state.adj_handlers),
    {reply, ok, State};
handle_call({clear_neighbors, Which}, _From, State) ->
    lists:map(
      fun(A) ->
	      case dict:find(A, State#state.adj_handlers) of
		  {ok, {_Sid, Pid}} ->
		      gen_fsm:send_event(Pid, stop);
		  _ -> ok
	      end
      end, Which),
    {reply, ok, State};
	

handle_call({dump_config, Name, Level}, _From, State) ->
    dump_config_state(Name, Level, State),
    {reply, ok, State};

handle_call(Request, _From, State) ->
    io:format("~s: Failed to handle message: ~p~n",
	      [?MODULE_STRING, Request]),
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
handle_cast({set, Values}, State) ->
    NewState = set_values(Values, State),
    {noreply, NewState};

handle_cast({send_pdu, Type, PDU, PDU_Size, _Level}, State) ->
    do_send_pdu(Type, PDU, PDU_Size, State),
    {noreply, State};

handle_cast(stop, #state{adj_handlers = Adjs,
			 iih_timer = IIHTimerRef,
			 dis_timer = DISTimerRef,
			 pdu_state = Pdu} = State) ->
    %% Cancel our timer
    cancel_timers([IIHTimerRef, Pdu#isis_pdu_state.ssn_timer, DISTimerRef]),
    %% Notify our adjacencies
    dict:map(fun(_From, {_, Pid}) -> gen_fsm:send_event(Pid, stop) end,
	     Adjs),
    NewState = relinquish_dis(State),
    {stop, normal, NewState};

handle_cast({received, From, PDU}, State) ->
    NewState = 
	case isis_interface_lib:verify_authentication(PDU, State#state.pdu_state) of
	    valid -> process_pdu(From, PDU, State);
	    Error ->
		isis_logger:info("Ignoring PDU, authentication ~p", [Error]),
		isis_logger:info("PDU failed checksum: ~p ~x", [Error, PDU]),
		State
	end,
    {noreply, NewState};


handle_cast({set_database}, #state{pdu_state = Pdu} = State) ->
    DB = isis_lspdb:get_db(State#state.level),
    PDUState = 
	#isis_pdu_state{
	   parent = ?MODULE,
	   parent_pid = self(),
	   interface_name = State#state.interface_name,
	   circuit_name = {interface, State#state.interface_name},
	   level = State#state.level,
	   system_id = isis_system:system_id(),
	   database = DB},
    Timer = start_timer(iih, State),
    {noreply, State#state{database = DB, iih_timer = Timer, pdu_state = PDUState}};

handle_cast({update_adjacency, up, Pid, {Sid, SNPA, Priority}}, State) ->
    D = dict:store(Pid, {Sid, SNPA, Priority}, State#state.up_adjacencies),
    case State#state.are_we_dis of
	true ->
	    update_reachability_tlv(add, <<Sid:6/binary, 0:8>>,
				    State#state.pseudonode, 0, State);
	_ ->
	    %% update_reachability_tlv(add, <<Sid:6/binary, 0:8>>,
	    %% 			    0, State#state.metric, State)
	    ok
    end,
    {noreply, State#state{up_adjacencies = D}};
handle_cast({update_adjacency, down, Pid, {Sid, _, _}}, State) ->
    %% io:format("Adjacency with ~p now down~n", [Sid]),
    D = dict:erase(Pid, State#state.up_adjacencies),
    case State#state.are_we_dis of
	true -> update_reachability_tlv(del, <<Sid:6/binary, 0:8>>,
				       State#state.pseudonode, 0, State);
	_ -> ok
    end,
    {noreply, State#state{up_adjacencies = D}};
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
handle_info({timeout, _Ref, iih}, State) ->
    cancel_timers([State#state.iih_timer]),
    send_iih(State),
    Timer = start_timer(iih, State),
    {noreply, State#state{iih_timer = Timer}};

handle_info({timeout, _Ref, ssn}, #state{pdu_state = Pdu} = State) ->
    NewPDU = isis_interface_lib:send_psnp(Pdu#isis_pdu_state{ssn_timer = undef}),
    {noreply, State#state{pdu_state = NewPDU}};

handle_info({timeout, _Ref, dis},
	    #state{are_we_dis = true, pdu_state = Pdu} = State) ->
    cancel_timers([Pdu#isis_pdu_state.ssn_timer]),
    NewPdu = isis_interface_lib:send_csnp(Pdu#isis_pdu_state{ssn_timer = undef}),
    Timer = start_timer(dis, State),
    {noreply, State#state{dis_timer = Timer, pdu_state = NewPdu}};
handle_info({timeout, _Ref, dis}, State) ->
    {noreply, State#state{dis_timer = undef}};

handle_info({'DOWN', _Ref, process, Pid, _Reason}, State) ->
    %% Remove adjacency...
    {noreply, remove_adj_by_pid(Pid, State)};

handle_info(Info, State) ->
    io:format("~s: Failed to handle message: ~p~n",
	      [?MODULE_STRING, Info]),
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
handle_iih(_, _, #state{system_id = SID} = State) when SID =:= undefined ->
    %% Ignore IIH until we have a system id...
    isis_logger:debug("Ignoring IIH as no system_id set"),
    State;
handle_iih(From, IIH, #state{adj_handlers = Adjs} = State) ->
    {NewAdjs, NewUpAdjs, AdjPid} = 
	case dict:find(From, Adjs) of
	    {ok, {_SID, Pid}} ->
		gen_fsm:send_event(Pid, {iih, IIH}),
		UpAdj2 = 
		    case dict:find(Pid, State#state.up_adjacencies) of
			{ok, {A, B, _P}} ->
			    dict:store(Pid, {A, B, IIH#isis_iih.priority},
				       State#state.up_adjacencies);
			_ -> State#state.up_adjacencies
		    end,
		{Adjs, UpAdj2, Pid};
	    _ ->
		%% Start adj handler...
		{ok, NewPid} = isis_adjacency:start_link([{neighbor, From},
							  {interface, State#state.interface_ref,
							   State#state.interface_name},
							  {snpa, State#state.snpa},
							  {mode, State#state.mode},
							  {level, IIH#isis_iih.pdu_type},
							  {level_pid, self()},
							  {metric, State#state.metric}]),
		erlang:monitor(process, NewPid),
		gen_fsm:send_event(NewPid, {iih, IIH}),
		{dict:store(From, {IIH#isis_iih.source_id, NewPid}, Adjs), State#state.up_adjacencies, NewPid}
	end,
    AdjState = State#state{adj_handlers = NewAdjs, up_adjacencies = NewUpAdjs},
    isis_logger:debug("DIS Election on ~s: Us: ~B, Them: ~B From > Our: ~p (From: ~p, Our ~p)",
               [State#state.interface_name,
                State#state.priority, IIH#isis_iih.priority,
                (From > State#state.snpa),
               From, State#state.snpa]),
    case dict:find(AdjPid, AdjState#state.up_adjacencies) of
	{ok, _} -> handle_dis_election(From, IIH, AdjState);
	_ -> AdjState
    end.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% 
%% Handle DIS Election.
%%   If the IIH has a priority thats higher than ours, or the SNPA is higher,
%%     then we believe who they think is DIS
%%   Else
%%     If we have an adjacency with the DIS, we must have lost.
%%     Otherwise, try to become the DIS
%%
%% @end
%%--------------------------------------------------------------------
-spec handle_dis_election(binary(), isis_iih(), tuple()) -> tuple().
handle_dis_election(From, 
		    #isis_iih{priority = TheirP, dis = <<D:6/binary, DPN:8>> = DIS, source_id = SID},
		    #state{priority = OurP, snpa = OurSNPA, dis = CurrentDIS} = State)
  when TheirP > OurP; TheirP == OurP, From > OurSNPA ->
    DIS_Priority = 
	case D =:= SID of
	    true -> TheirP;
	    _ -> State#state.dis_priority
	end,
    case State#state.are_we_dis of
	true -> relinquish_dis(State);
	_ -> ok
    end,
    NewState = 
	case DPN =:= 0 of
	    true -> State#state{dis_priority = DIS_Priority, are_we_dis = false};
	    _ -> case State#state.dis =:= DIS of
		     false -> update_reachability_tlv(add, DIS, 0, State#state.metric, State),
			      update_reachability_tlv(del, CurrentDIS, 0, State#state.metric, State); 
		     _ -> ok
		 end,
		 State#state{dis = DIS, dis_priority = DIS_Priority, are_we_dis = false}
	end,
    NewState;
handle_dis_election(_From,
		    #isis_iih{},
		    #state{priority = OurP, are_we_dis = Us, snpa = OurM} = State)
  when Us =:= false ->
    %% Any one else likely to take over?
    isis_logger:debug("up_adj: ~p", [dict:to_list(State#state.up_adjacencies)]),
    BetterAdj = dict:to_list(
		  dict:filter(
		    fun(_, {_, _, P}) when P > OurP -> true;
		       (_, {_, M, P}) when P =:= OurP, M > OurM -> true;
		       (_, {_, _, _}) -> false
		    end, State#state.up_adjacencies)),
    isis_logger:debug("DIS Election: we beat adj, but not these: ~p", [BetterAdj]),
    case length(BetterAdj) of
	0 -> assume_dis(State);
	_ -> State
    end;
handle_dis_election(_From,
		    #isis_iih{priority = _TheirP, dis = _DIS, source_id = _SID},
		    #state{priority = _OurP, are_we_dis = _Us} = State) ->
    State.

assume_dis(State) ->
    %% Get pseudo-node here, create LSP etc..
    Node = isis_system:allocate_pseudonode(self(), State#state.level),
    isis_logger:info("Allocated pseudo-node ~p to ~p ~s~n",
	       [Node, State#state.level,  State#state.interface_name]),
    DIS_Timer = start_timer(dis, State),
    ID = State#state.system_id,
    SysID = <<ID:6/binary, 0:8>>,
    DIS = <<ID:6/binary, Node:8>>,
    NewState = State#state{dis = DIS, dis_timer = DIS_Timer,
			   are_we_dis = true, pseudonode = Node},
    %% Add our relationship to the DIS to our LSP
    update_reachability_tlv(add, DIS, 0, State#state.metric, State),
    %% Remove our relationship with the old DIS, and link DIS to new node
    update_reachability_tlv(del, State#state.dis, 0, 0, State),
    update_reachability_tlv(add, SysID, Node, 0, State),
    dict:map(fun(_, {AdjID, _, _}) -> 
		     update_reachability_tlv(add, <<AdjID:6/binary, 0:8>>, Node, 0, State)
	     end, State#state.up_adjacencies),
    isis_system:schedule_lsp_refresh(),
    send_iih(NewState),
    NewState.

relinquish_dis(#state{are_we_dis = true,
		      dis = DIS,
		      pseudonode = Node} = State) ->
    %% Unlink our LSP from our DIS LSP...
    update_reachability_tlv(del, DIS, 0, 0, State),
    %% We're no longer DIS, so release pseudonode
    isis_system:deallocate_pseudonode(Node, State#state.level),
    State#state{dis = undef, are_we_dis = false, pseudonode = 0};
relinquish_dis(State) ->
    State.

remove_adjacency(#state{are_we_dis = false,
			dis = DIS,
			level = Level,
			interface_name = Interface})
  when DIS =/= undef ->
    TLV = 
	#isis_tlv_extended_reachability{
	   reachability = [#isis_tlv_extended_reachability_detail{
			      neighbor = DIS,
			      metric = 0,
			      sub_tlv = []}]},
    isis_system:delete_tlv(TLV, 0, Level, Interface);
remove_adjacency(_) ->
    ok.


%%--------------------------------------------------------------------
%% @private
%% @doc
%% 
%% Send an IIH message
%%
%% @end
%%--------------------------------------------------------------------
send_iih(#state{system_id = SID}) when SID =:= undefined; byte_size(SID) =/= 6 ->
    no_system_id;
send_iih(#state{system_id = SID,
		pdu_state = Pdu} = State) ->
    IS_Neighbors =
	lists:map(fun({A, _}) -> A end,
		  dict:to_list(State#state.adj_handlers)),
    Areas = isis_system:areas(),
    V4Addresses = get_addresses(State, ipv4),
    V6Addresses = 
	lists:sublist(lists:filter(fun(A) -> <<LL:16, _R:112>> = <<A:128>>, LL =:= 16#FE80 end,
				   get_addresses(State, ipv6)),
		     ?ISIS_IIH_IPV6COUNT),
    DIS = case State#state.dis of
	      undef -> <<0:(7*8)>>;
	      D -> D
	  end,
    {Circuit, PDUType} = 
	case State#state.level of
	    level_1 -> {level_1, level1_iih};
	    level_2 -> {level_1_2, level2_iih}
	end,
    ISNeighborsTLV = case length(IS_Neighbors) of
			 0 -> [];
			 _ -> [#isis_tlv_is_neighbors{neighbors = IS_Neighbors}]
		     end,
    IPv4TLV = case length(V4Addresses) of
		  0 -> [];
		  _ -> [#isis_tlv_ip_interface_address{addresses = V4Addresses}]
	      end,
    AreasTLV = case length(Areas) of
		   0 -> [];
		   _ -> [#isis_tlv_area_address{areas = Areas}]
	       end,
    IPv6TLV = case length(V6Addresses) of
		  0 -> [];
		  _ -> [#isis_tlv_ipv6_interface_address{addresses = V6Addresses}]
	      end,
    BaseTLVs = ISNeighborsTLV 	++ AreasTLV ++ IPv4TLV ++ IPv6TLV ++
	[#isis_tlv_protocols_supported{protocols = [ipv4, ipv6]}],
    TLVs = isis_protocol:authentication_tlv(Pdu#isis_pdu_state.authentication) ++ BaseTLVs,
    IIH = #isis_iih{
	     pdu_type = PDUType,
	     circuit_type = Circuit,
	     source_id = SID,
	     holding_time = erlang:trunc(State#state.hold_time / 1000),
	     priority = State#state.priority,
	     dis = DIS,
	     tlv = TLVs
	},
    {ok, _, PDU_Size} = isis_protocol:encode(IIH, Pdu#isis_pdu_state.authentication),
    PadTLVs = generate_padding(State#state.mtu - PDU_Size -3,
			       State),
    ActualIIH = IIH#isis_iih{tlv = TLVs ++ PadTLVs},
    {ok, SendPDU, SendPDU_Size} = isis_protocol:encode(ActualIIH,
						       Pdu#isis_pdu_state.authentication),
    do_send_pdu(iih, SendPDU, SendPDU_Size, State).

%%--------------------------------------------------------------------
%% @private
%% @doc
%% 
%% We've been notified an adj handler has terminated. Handle it
%% cleanly...
%%
%% @end
%%--------------------------------------------------------------------
remove_adj_by_pid(Pid, State) ->
    F = fun(_, {_,P}) when P =:= Pid ->
		false;
	   (_, _) -> true
	end,
    NewAdj = dict:filter(F, State#state.adj_handlers),
    case length(dict:fetch_keys(NewAdj)) of
	0 -> remove_adjacency(State),
	     NewState = relinquish_dis(State#state{adj_handlers = NewAdj}),
	     NewState#state{dis = undef};
	_ -> State#state{adj_handlers = NewAdj}
    end.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% 
%% Given a size, generate the appropriate number of padding TLVs to
%% fill that space IF padding is enabled. If padding is disabled, then
%% ignore (return an empty list).
%%
%% @end
%%--------------------------------------------------------------------
generate_padding(_Size, #state{padding = false}) ->
    [];
generate_padding(Size, State) ->
    generate_padding(Size, State, []).

generate_padding(Size, State, Acc) when Size > 257 ->
    generate_padding(Size - 257, State,
		     Acc ++ [#isis_tlv_padding{size = 255}]);
generate_padding(Size, _State, Acc) ->
    Acc ++ [#isis_tlv_padding{size = (Size - 2)}].


-spec process_pdu(binary(), isis_pdu(), tuple()) -> tuple().
process_pdu(From, #isis_iih{} = IIH, State) ->
    case valid_iih(From, IIH, State) of
	true -> handle_iih(From, IIH, State);
	false -> State
    end;
process_pdu(_From, #isis_lsp{} = LSP,
	    #state{pdu_state = Pdu} = State) ->
    isis_logger:debug("Handling LSP: ~p", [LSP]),
    NewPDU = Pdu#isis_pdu_state{are_we_dis = State#state.are_we_dis},
    isis_interface_lib:handle_lsp(LSP, NewPDU),
    State;
process_pdu(_From, #isis_csnp{} = CSNP,
	    #state{pdu_state = Pdu} = State) ->
    NewPDU = isis_interface_lib:handle_csnp(CSNP, Pdu),
    State#state{pdu_state = NewPDU};
process_pdu(_From, #isis_psnp{} = PSNP,
	    #state{pdu_state = Pdu} = State) ->
    isis_interface_lib:handle_psnp(PSNP, Pdu),
    State;
process_pdu(_, _, State) ->
    State.

-spec cancel_timers(list()) -> ok.
cancel_timers([H | T]) when H /= undef ->    
    erlang:cancel_timer(H),
    cancel_timers(T);
cancel_timers([H | T]) when H == undef -> 
    cancel_timers(T);
cancel_timers([]) -> 
    ok.

-spec start_timer(atom(), tuple()) -> reference().
start_timer(dis, #state{pdu_state = PDU, csnp_timer = CT}) ->
    case PDU#isis_pdu_state.dis_continuation of
	undef ->
	    erlang:start_timer(isis_protocol:jitter(CT, ?ISIS_CSNP_JITTER),
			       self(), dis);
	_ ->
	    erlang:start_timer(erlang:trunc(?ISIS_CSNP_PACE_TIMER), self(), dis)
    end;
start_timer(iih, State) ->
    erlang:start_timer(isis_protocol:jitter(State#state.hello_interval,
					    ?ISIS_HELLO_JITTER), self(), iih).

%%--------------------------------------------------------------------
%% @private
%% @doc
%%
%% Pass the PDU to be sent up to the interface, as that has the socket
%% and ability to send the frame.
%%
%% @end
%%--------------------------------------------------------------------
do_send_pdu(Type, PDU, PDU_Size, State) ->
    isis_interface:send_pdu(State#state.interface_ref, Type, 
			    PDU, PDU_Size,
			    State#state.level).

parse_args([{level, L} | T], State) ->
    parse_args(T, State#state{level = L});
parse_args([{snpa, M} | T], State) ->
    parse_args(T, State#state{snpa = M});
parse_args([{mode, broadcast} | T], State) ->
    parse_args(T, State#state{mode = broadcast});
parse_args([{mode, point_to_multipoint} | T], State) ->
    parse_args(T, State#state{mode = broadcast});
parse_args([{interface, N, I, M} | T], State) ->
    parse_args(T, State#state{interface_ref = I,
			      interface_name = N,
			      mtu = M});
parse_args([], State) ->
    State.

set_values([{encryption, none, _Key} | Vs],
	   #state{pdu_state = PDU} = State) ->
    NewPDU = PDU#isis_pdu_state{authentication = none},
    set_values(Vs, State#state{pdu_state = NewPDU});
set_values([{encryption, text, Key} | Vs], 
	   #state{pdu_state = PDU} = State) ->
    NewPDU = PDU#isis_pdu_state{authentication = {text, Key}},
    set_values(Vs, State#state{pdu_state = NewPDU});
set_values([{encryption, md5, Key} | Vs],
	   #state{pdu_state = PDU} = State) ->
    NewPDU = PDU#isis_pdu_state{authentication = {md5, Key}},
    set_values(Vs, State#state{pdu_state = NewPDU});
set_values([{level_authentication, Crypto} | Vs],
	   #state{pdu_state = PDU} = State) ->
    NewPDU = PDU#isis_pdu_state{level_authentication = Crypto},
    set_values(Vs, State#state{pdu_state = NewPDU});
set_values([{metric, M} | Vs], State) ->
    set_values(Vs, State#state{metric = M});
set_values([{csnp_timer, T} | Vs], State) ->
    set_values(Vs, State#state{csnp_timer = T});
set_values([{priority, P} | Vs], State) ->
    set_values(Vs, State#state{priority = P});
set_values([{hold_time, P} | Vs], State) ->
    set_values(Vs, State#state{hold_time = P * 1000});
set_values([{hello_interval, P} | Vs], State) ->
    set_values(Vs, State#state{hello_interval = P * 1000});
set_values([{csnp_interval, P} | Vs], State) ->
    set_values(Vs, State#state{csnp_timer = P * 1000});
set_values([{system_id, SID} | Vs], State) ->
    PDU = State#state.pdu_state,
    NewPDU = PDU#isis_pdu_state{system_id = SID},
    set_values(Vs, State#state{system_id = SID,
			       pdu_state = NewPDU});
set_values([_ | Vs], State) ->
    set_values(Vs, State);
set_values([], State) ->
    State.


%%--------------------------------------------------------------------
%% @private
%% @doc
%%
%% Validate the IIH before we process it...
%%
%% @end
%%--------------------------------------------------------------------
valid_iih(_From, IIH, State) ->
    valid_iih_ps(IIH, State) and
	valid_iih_area(IIH, State).

%% Checks we have a valid protocol supported field
valid_iih_ps(IIH, _State) ->
    PS = isis_protocol:filter_tlvs(isis_tlv_protocols_supported,
				   IIH#isis_iih.tlv),
    case length(PS) of
	0 -> false;
	_ -> true
    end.

% Checks we have an intersection area
valid_iih_area(_IIH, #state{level = level_2}) ->
    true;
valid_iih_area(IIH, #state{level = level_1}) ->
    IIHAreas = 
	lists:foldl(fun(#isis_tlv_area_address{areas = A}, Acc) ->
			    Acc ++ A;
		       (_, Acc) ->
			    Acc
		    end, [], IIH#isis_iih.tlv),
    SysAreas = isis_system:areas(),
    S1 = sets:from_list(IIHAreas),
    S2 = sets:from_list(SysAreas),
    case length(sets:to_list(sets:intersection(S1, S2))) of
	0 -> false;
	_ -> true
    end.
	     
	    

do_update_reachability_tlv(add, N, PN, Metric,
			   #state{metric_type = narrow} = State) ->
    TLV = #isis_tlv_is_reachability{
	     virtual = false,
	     is_reachability = [#isis_tlv_is_reachability_detail{
				   neighbor = N,
				   default = #isis_metric_information{metric_supported = true,
								      metric = Metric,
								      metric_type = internal}}]},
    isis_system:update_tlv(TLV, PN, State#state.level, State#state.interface_name);
do_update_reachability_tlv(del, N, PN, Metric,
			   #state{metric_type = narrow} = State) ->
    TLV = #isis_tlv_is_reachability{
	     virtual = false,
	     is_reachability = [#isis_tlv_is_reachability_detail{
				   neighbor = N,
				   default = #isis_metric_information{metric_supported = true,
								      metric = Metric,
								      metric_type = internal}}]},
    isis_system:delete_tlv(TLV, PN, State#state.level, State#state.interface_name);
do_update_reachability_tlv(add, N, PN, Metric,
			   #state{metric_type = wide} = State) ->
    TLV = #isis_tlv_extended_reachability{
	     reachability = [#isis_tlv_extended_reachability_detail{
				neighbor = N,
				metric = Metric,
				sub_tlv = []}]},
    isis_system:update_tlv(TLV, PN, State#state.level, State#state.interface_name);
do_update_reachability_tlv(del, N, PN, Metric,
			   #state{metric_type = wide} = State) ->
    TLV = #isis_tlv_extended_reachability{
	     reachability = [#isis_tlv_extended_reachability_detail{
				neighbor = N,
				metric = Metric,
				sub_tlv = []}]},
    isis_system:delete_tlv(TLV, PN, State#state.level, State#state.interface_name).

update_reachability_tlv(Dir, <<_:6/binary, PN:8>> = N, 0, Metric, State) when PN =:= 0 ->
    isis_logger:info("Updating reachability TLV ~s neighbor ~p (pseudonode ~B) ~s",
	       [Dir, N, 0, State#state.interface_name]),
    do_update_reachability_tlv(Dir, N, PN, Metric, State);
update_reachability_tlv(Dir, N, PN, Metric, State) ->
    isis_logger:info("Updating reachability TLV ~s neighbor ~p (pseudonode ~B) ~s",
	       [Dir, N, PN, State#state.interface_name]),
    do_update_reachability_tlv(Dir, N, PN, Metric, State).

dump_config_fields(Name, Level,
		   [{authentication, {text, K}} | Fs],
		   State) ->
    io:format("isis_system:set_interface(\"~s\", ~s, [{encryption, ~s, ~p}]).~n",
	      [Name, Level, text, K]),
    dump_config_fields(Name, Level, Fs, State);
dump_config_fields(Name, Level,
		   [{authentication, {md5, K}} | Fs],
		   State) ->
    io:format("isis_system:set_interface(\"~s\", ~s, [{encryption, ~s, ~p}]).~n",
	      [Name, Level, md5, K]),
    dump_config_fields(Name, Level, Fs, State);
dump_config_fields(Name, Level,
		   [{metric, M} | Fs], State)
  when M =/= ?DEFAULT_METRIC ->
    io:format("isis_system:set_interface(\"~s\", ~s, [{metric, ~p}]).~n",
	      [Name, Level, M]),
    dump_config_fields(Name, Level, Fs, State);
dump_config_fields(Name, Level,
		   [{priority, M} | Fs], State)
 when M =/= 64 ->
    io:format("isis_system:set_interface(\"~s\", ~s, [{priority, ~p}]).~n",
	      [Name, Level, M]),
    dump_config_fields(Name, Level, Fs, State);
dump_config_fields(Name, Level,
		   [{hello_interval, M} | Fs], State)
  when M =/= (?DEFAULT_HOLD_TIME / 3) ->
    io:format("isis_system:set_interface(\"~s\", ~s, [{hello_interval, ~p}]).~n",
	      [Name, Level, erlang:trunc(M/1000)]),
    dump_config_fields(Name, Level, Fs, State);
dump_config_fields(Name, Level,
		   [{hold_time, M} | Fs], State)
  when M =/= ?DEFAULT_HOLD_TIME ->
    io:format("isis_system:set_interface(\"~s\", ~s, [hold_time, ~p}]).~n",
	      [Name, Level, erlang:trunc(M/1000)]),
    dump_config_fields(Name, Level, Fs, State);
dump_config_fields(Name, Level, [_ | Fs], State) ->
    dump_config_fields(Name, Level, Fs, State);
dump_config_fields(_, _, [], _) ->
    ok.

dump_config_state(Name, Level, State) ->
    S = lists:zip(record_info(fields, state),
		  tl(erlang:tuple_to_list(State))),
    dump_config_fields(Name, Level, S, State).

get_addresses(State, Family) ->
    Matcher = fun(#isis_address{afi = F, address = A})
		    when F =:= Family -> {true, A};
 		 (_) -> false
 	      end,
    case isis_system:get_interface(State#state.interface_name) of
	unknown -> [];
	Interface -> 
	    lists:filtermap(Matcher,
			    Interface#isis_interface.addresses)
    end.
