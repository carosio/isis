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

%% API
-export([start_link/1, get_state/1, get_state/2, set/2,
	 update_adjacency/3, clear_neighbors/2,
	 dump_config/3]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3,
	 handle_pdu/3, stop/1]).

-define(SERVER, ?MODULE).

-record(state, {
	  level,           %% The level
	  interface_ref,   %% Interface
	  interface_name,
	  system_id,       %% Cached system_id
	  snpa,            %% Our mac address
	  mtu,
	  database = undef, %% The LSPDB reference
	  hello_interval = (?DEFAULT_HOLD_TIME / 3),
	  hold_time = ?DEFAULT_HOLD_TIME,
	  csnp_timer = ?ISIS_CSNP_TIMER,
	  metric = ?DEFAULT_METRIC,
	  metric_type = wide :: wide | narrow,
	  authentication_type = none :: none | text | md5,
	  authentication_key = <<>>,
	  padding = true :: true | false,  %% To pad or not...
	  iih_timer = undef :: reference() | undef, %% iih timer for this level
	  ssn_timer = undef :: reference() | undef, %% SSN timer
	  adj_handlers,     %% Dict for SNPA -> FSM pid
	  up_adjacencies,  %% Dict for Pid -> SID (populated by adj fsm when adj is up)
	  priority = 64,   %% 0 - 127 (6 bit) for our priority, highest wins
	  dis = undef,     %% Current DIS for this interface ( 7 bytes, S-id + pseudonode)
	  dis_priority,    %% Current DIS's priority
	  are_we_dis = false,  %% True if we're the DIS
	  pseudonode = 0,  %% Allocated pseudonode if we're DIS
	  dis_continuation = undef,%% Do we have more CSNP's to send?
	  dis_timer = undef :: reference() | undef, %% If we're DIS, we use this timer to announce CSNPs
	  ssn = [] :: [binary()]  %% list of pending
	 }).

%%%===================================================================
%%% API
%%%===================================================================
handle_pdu(Pid, From, PDU) ->
    gen_server:cast(Pid, {received, From, PDU}).

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
    send_iih(State),
    {reply,ok, State};

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
handle_call({get_state, authentication}, _From, State) ->
    {reply, {State#state.authentication_type,
	     State#state.authentication_key}, State};
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

handle_cast(stop, #state{adj_handlers = Adjs,
			 iih_timer = IIHTimerRef,
			 ssn_timer = SSNTimerRef,
			 dis_timer = DISTimerRef} = State) ->
    %% Cancel our timer
    cancel_timers([IIHTimerRef, SSNTimerRef, DISTimerRef]),
    %% Notify our adjacencies
    dict:map(fun(_From, {_, Pid}) -> gen_fsm:send_event(Pid, stop) end,
	     Adjs),
    NewState = relinquish_dis(State),
    {stop, normal, NewState};

handle_cast({received, From, PDU}, State) ->
    NewState = 
	case verify_authentication(PDU, State) of
	    valid -> process_pdu(From, PDU, State);
	    _ -> State
	end,
    {noreply, NewState};


handle_cast({set_database}, State) ->
    DB = isis_lspdb:get_db(State#state.level),
    Timer = start_timer(iih, State),
    {noreply, State#state{database = DB, iih_timer = Timer}};

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

handle_info({timeout, _Ref, ssn}, State) ->
    cancel_timers([State#state.ssn_timer]),
    NewState = send_psnp(State#state{ssn_timer = undef}),
    {noreply, NewState};

handle_info({timeout, _Ref, dis},
	    #state{are_we_dis = true} = State) ->
    cancel_timers([State#state.ssn_timer]),
    NewState = send_csnp(State),
    Timer = start_timer(dis, NewState),
    {noreply, NewState#state{dis_timer = Timer}};
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
send_iih(#state{system_id = SID} = State) ->
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
    TLVs = authentication_tlv(State) ++ BaseTLVs,
    IIH = #isis_iih{
	     pdu_type = PDUType,
	     circuit_type = Circuit,
	     source_id = SID,
	     holding_time = erlang:trunc(State#state.hold_time / 1000),
	     priority = State#state.priority,
	     dis = DIS,
	     tlv = TLVs
	},
    {ok, _, PDU_Size} = isis_protocol:encode(IIH),
    PadTLVs = generate_padding(State#state.mtu - PDU_Size -3,
			       State),
    ActualIIH = IIH#isis_iih{tlv = TLVs ++ PadTLVs},
    {ok, SendPDU, SendPDU_Size} = isis_protocol:encode(ActualIIH),
    send_pdu(iih, SendPDU, SendPDU_Size, State).


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

%%--------------------------------------------------------------------
%% @private
%% @doc
%% 
%% Extract the database in a series of chunks ready to turn into CSNP
%% packets. We pace these out at a rate to avoid deludging the LAN.
%%
%% @end
%%--------------------------------------------------------------------
send_csnp(#state{database = DBRef, dis_continuation = DC} = State) ->
    Args = case DC of
	       undef -> {start, 90};
	       _ -> {continue, DC}
	   end,
    {Summary, Continue} = isis_lspdb:summary(Args, DBRef),
    NextDC = 
	case generate_csnp(Args, 90, Summary, State) of
	    ok ->
		case Continue of
		    '$end_of_table' -> undef;
		    _ -> Continue
		end;
	    _ -> undef
	end,
    State#state{dis_continuation = NextDC}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% 
%% Take a series of LSP Detail summaries that have been extracted from
%% the database and package them up into TLVs and then place the TLVs
%% into the CSNP. We do a little work to calculate the start and end
%% lsp-id of this CSNP message.
%%
%% @end
%%--------------------------------------------------------------------
generate_csnp(_, _, _, #state{system_id = SID}) when SID =:= undefined ->
    no_system_id;
generate_csnp({Status, _}, Chunk_Size, Summary,
	      #state{system_id = Sys_ID} = State) ->
    Source = <<Sys_ID:6/binary, 0:8>>,
    PDU_Type =
	case State#state.level of
	    level_1 -> level1_csnp;
	    level_2 -> level2_csnp
	end,
    {Start, End} = 
	case length(Summary) of
	    0 -> {<<255,255,255,255,255,255,255,255>>,
		  <<255,255,255,255,255,255,255,255>>};
	    _ ->
		%% If this is teh start, our 'first' lsp is all-zeros
		TStart =
		    case Status of
			start -> <<0,0,0,0,0,0,0,0>>;
			_ ->
			    %% Extract first LSP-ID
			    {SID, _, _, _} = lists:nth(1, Summary),
			    SID
		    end,
		%% If this is the end, all-ones
		TEnd = 
		    case  length(Summary) == Chunk_Size of
			true ->
			    %% Extract last LSP-ID
			    {LID, _, _, _} = lists:last(Summary),
			    LID;
			_ -> <<255,255,255,255,255,255,255,255>>
		    end,
		{TStart, TEnd}
	end,
    Details = lists:map(fun({ID, Seq, Check, Lifetime}) ->
				LF = case Lifetime > 0 of
					 true -> Lifetime;
					 _ -> 0
				     end,
				#isis_tlv_lsp_entry_detail{lsp_id = ID,
							   sequence = Seq,
							   checksum = Check,
							   lifetime = LF}
			end, Summary),
    DetailPackageFun = fun(F) -> [#isis_tlv_lsp_entry{lsps = F}] end,
    TLVs = authentication_tlv(State)
	++ isis_protocol:package_tlvs(Details, DetailPackageFun,
				      ?LSP_ENTRY_DETAIL_PER_TLV),
    CSNP = #isis_csnp{pdu_type = PDU_Type,
		      source_id = Source,
		      start_lsp_id = Start,
		      end_lsp_id = End,
		      tlv = TLVs},
    {ok, PDU, PDU_Size} = isis_protocol:encode(CSNP),
    send_pdu(csnp, PDU, PDU_Size, State),
    ok.

-spec process_pdu(binary(), isis_pdu(), tuple()) -> tuple().
process_pdu(From, #isis_iih{} = IIH, State) ->
    case valid_iih(From, IIH, State) of
	true -> handle_iih(From, IIH, State);
	false -> State
    end;
process_pdu(_From, #isis_lsp{} = LSP, State) ->
    isis_logger:debug("Handling LSP: ~p", [LSP]),
    handle_lsp(LSP, State),
    State;
process_pdu(_From, #isis_csnp{} = CSNP, State) ->
    handle_csnp(CSNP, State);
process_pdu(_From, #isis_psnp{} = PSNP, State) ->
    handle_psnp(PSNP, State),
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
start_timer(dis, #state{dis_continuation = DC, csnp_timer = CT}) when DC == undef ->
    erlang:start_timer(isis_protocol:jitter(CT, ?ISIS_CSNP_JITTER),
		      self(), dis);
start_timer(dis, _State) ->
    erlang:start_timer(erlang:trunc(?ISIS_CSNP_PACE_TIMER), self(), dis);
start_timer(iih, State) ->
    erlang:start_timer(isis_protocol:jitter(State#state.hello_interval,
					    ?ISIS_HELLO_JITTER), self(), iih);
start_timer(ssn, _State) ->
    erlang:start_timer(isis_protocol:jitter(?ISIS_PSNP_TIMER, ?ISIS_PSNP_JITTER),
		      self(), ssn).

%%--------------------------------------------------------------------
%% @private
%% @doc
%% 
%% Take 2 lists of isis_lsp_tlv_entry_details - the first from our
%% database, the second from the CSNP packet. We iterate the lists:
%%   If the LSP is on the first, but not the second, we need to announce
%%   If the LSP is on the second, but not eh first - we must request it
%%   If the LSP is on both, check the sequence number...
%% The reason to do it this way is efficiency...
%%
%% @end
%%--------------------------------------------------------------------
-spec compare_lsp_entries([isis_tlv_lsp_entry_detail()],
			  [isis_tlv_lsp_entry_detail()], {[binary()], [binary()]}) ->
				 {[binary()], [binary()]}.
compare_lsp_entries([#isis_tlv_lsp_entry_detail{lsp_id = L, sequence = LN} | LT],
		    [#isis_tlv_lsp_entry_detail{lsp_id = H, sequence = HN} | HT],
		    {Request, Announce})
  when L == H, LN < HN ->
    compare_lsp_entries(LT, HT, {[L | Request], Announce});
compare_lsp_entries([#isis_tlv_lsp_entry_detail{lsp_id = L, sequence = LN} | LT],
		    [#isis_tlv_lsp_entry_detail{lsp_id = H, sequence = HN} | HT],
		    {Request, Announce})
  when L == H, LN > HN ->
    compare_lsp_entries(LT, HT, {Request, [H | Announce]});
compare_lsp_entries([#isis_tlv_lsp_entry_detail{lsp_id = L, sequence = LN} | LT],
		    [#isis_tlv_lsp_entry_detail{lsp_id = H, sequence = HN} | HT],
		    {Request, Announce})
  when L == H, LN == HN ->
    compare_lsp_entries(LT, HT, {Request, Announce});
compare_lsp_entries([#isis_tlv_lsp_entry_detail{lsp_id = L} | LT],
		    [#isis_tlv_lsp_entry_detail{lsp_id = H} | _HT] = L2,
		    {Request, Announce})
  when L < H ->
    compare_lsp_entries(LT, L2, {Request, [L | Announce]});
compare_lsp_entries([#isis_tlv_lsp_entry_detail{lsp_id = L} | _LT] = L1,
		    [#isis_tlv_lsp_entry_detail{lsp_id = H} | HT],
		    {Request, Announce})
  when L > H ->
    compare_lsp_entries(L1, HT, {[H | Request], Announce});
compare_lsp_entries([],
		    [#isis_tlv_lsp_entry_detail{lsp_id = H} | HT],
		    {Request, Announce}) ->
    %% We're missing an LSP, add to the request list
    compare_lsp_entries([], HT, {[H | Request], Announce});
compare_lsp_entries([#isis_tlv_lsp_entry_detail{lsp_id = L} | LT],
		    [],
		    {Request, Announce}) ->
    %% We have the LSP but the neighbor doesn't, so add to the announce list
    compare_lsp_entries(LT, [], {Request, [L | Announce]});
compare_lsp_entries([], [], {Request, Announce}) ->
    {lists:reverse(Request), lists:reverse(Announce)}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% 
%% Given a list of LSPs, announce them...
%%
%% @end
%%--------------------------------------------------------------------
-spec announce_lsps(list(), tuple()) -> ok.
announce_lsps(IDs, State) ->
    LSPs = isis_lspdb:lookup_lsps(lists:sort(IDs), State#state.database),
    send_lsps(LSPs, State),
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% 
%% Given a list of LSPs, send them out....
%%
%% @end
%%--------------------------------------------------------------------
-spec send_lsps([isis_lsp()], tuple()) -> ok.
send_lsps(LSPs, State) ->
    %% AuthTLV = authentication_tlv(State),
    lists:map(fun(#isis_lsp{} = L) ->
		      %% NewTLVs = AuthTLV ++ TLVs,
		      try isis_protocol:encode(L) of
			  {ok, Bin, Len} -> send_pdu(lsp, Bin, Len, State);
			  _ -> isis_logger:error("Failed to encode LSP ~p~n",
					   [L#isis_lsp.lsp_id])
		      catch
			  error:Fail ->
			      isis_logger:error("Failed to encode: ~p (~p)", [L, Fail])
		      end
	      end, LSPs),
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% 
%% Add the list of LSPs to the SSN gb_trees, ready to be sent. Start
%% the timer running if one isn't already running.
%%
%% @end
%%--------------------------------------------------------------------
-spec update_ssn([binary()], tuple()) -> tuple().
update_ssn(LSP_Ids, #state{ssn = SSN} = State) ->
    Timer = 
	case State#state.ssn_timer of
	    undef -> start_timer(ssn, State);
	    _ -> State#state.ssn_timer
	end,
    L = SSN ++ LSP_Ids,
    State#state{ssn = L, ssn_timer = Timer}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% 
%% Take the list of LSP IDs in the SSN field, and generate the PSNP
%% messages.
%%
%% @end
%%--------------------------------------------------------------------
-spec send_psnp(tuple()) -> tuple().
send_psnp(#state{ssn = SSN} = State) ->
    SID = State#state.system_id,
    Source = <<SID:6/binary, 0:8>>,
    PDU_Type =
	case State#state.level of
	    level_1 -> level1_psnp;
	    level_2 -> level2_psnp
	end,
    AuthTLV = authentication_tlv(State),
    TLVs = 
	lists:map(fun(LSP) -> #isis_tlv_lsp_entry_detail{lsp_id = LSP} end,
		  SSN),

    DetailPackageFun = fun(F) -> [#isis_tlv_lsp_entry{lsps = F}] end,			 
    TLVPackageFun = fun(F) -> [#isis_psnp{pdu_type = PDU_Type,
					  source_id = Source,
					  tlv = AuthTLV ++ F}]
		    end,

    %% Now we have the detail entries we need to bundle up as many
    %% entries as can be fitted into the 255 byte TLV limit and then
    %% as many TLVs as can be fitted into a messgae (based on MTU).
    List_of_TLVs = isis_protocol:package_tlvs(TLVs, DetailPackageFun,
					      ?LSP_ENTRY_DETAIL_PER_TLV),
    List_of_PDUs = isis_protocol:package_tlvs(List_of_TLVs, TLVPackageFun,
					      ?LSP_ENTRY_PER_PDU),
    lists:map(fun(F) ->
		      case isis_protocol:encode(F) of
			  {ok, Bin, Len} -> send_pdu(psnp, Bin, Len, State);
			  _ -> io:format("Bad encoding for ~p~n", [F])
		      end
	      end,
	      List_of_PDUs),
    State#state{ssn = []}.
		     
%%--------------------------------------------------------------------
%% @private
%% @doc
%%
%% A PSNP is either ack-ing an LSP we've sent, or its requesting
%% specific LSPs. So if the sequence number is set, then we should
%% send the LSP. Otherwise, there's nothing to do.
%%
%% @end
%%--------------------------------------------------------------------
-spec handle_psnp(isis_psnp(), tuple()) -> ok | error.
handle_psnp(_, #state{database = DB} = State) when DB =:= undef ->
    State;
handle_psnp(#isis_psnp{tlv = TLVs}, State) ->
    %% Extract and create lsp_entry_detail records for the range from
    %% our datbase
    PSNP_LSPs =
	lists:foldl(fun(F, Acc) ->
			    case is_record(F, isis_tlv_lsp_entry) of
				true -> Acc ++ F#isis_tlv_lsp_entry.lsps;
				_ -> Acc
			    end
		    end,
		    [], TLVs),
    %% FilterFun = fun(#isis_tlv_lsp_entry_detail{lifetime = L, sequence = S, checksum = C}) ->
    %% 			(L == 0) and (S == 0) and (C == 0)
    %% 		end,
    %% Filtered = lists:filter(FilterFun, PSNP_LSPs),
    %% LSP_Ids = lists:map(fun(F) -> F#isis_tlv_lsp_entry_detail.lsp_id end, Filtered),
    LSP_Ids = lists:map(fun(F) -> F#isis_tlv_lsp_entry_detail.lsp_id end, PSNP_LSPs),
    LSPs = isis_lspdb:lookup_lsps(LSP_Ids, State#state.database),
    send_lsps(LSPs, State),
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%%
%% A PSNP is either ack-ing an LSP we've sent, or its requesting
%% specific LSPs. So if the sequence number is set, then we should
%% send the LSP. Otherwise, there's nothing to do.
%%
%% @end
%%--------------------------------------------------------------------
-spec handle_lsp(isis_lsp(), tuple()) -> tuple().
handle_lsp(#isis_lsp{lsp_id = ID, remaining_lifetime = 0} = LSP, State) ->
    %% Purging the lsp...
    isis_logger:info("Purging LSP ~p", [ID]),
    isis_lspdb:store_lsp(State#state.level,
			 LSP#isis_lsp{tlv = [],
				      remaining_lifetime = 0,
				      last_update = isis_protocol:current_timestamp()});
handle_lsp(#isis_lsp{lsp_id = ID, sequence_number = TheirSeq} = LSP,
	   State) ->
    <<RemoteSys:6/binary, _Rest/binary>> = ID,
    case RemoteSys =:= State#state.system_id of
	true -> handle_old_lsp(LSP, State);
	_ ->
	    L = isis_lspdb:lookup_lsps([ID], State#state.database),
	    Announce = 
		case length(L) of
		    1 -> [OurLSP] = L,
			 OurSeq = OurLSP#isis_lsp.sequence_number,
			 case (OurSeq < TheirSeq) of
			     true -> isis_lspdb:store_lsp(State#state.level, LSP),
				     isis_logger:warning("Updated LSP (~b vs ~b)~n", [OurSeq, TheirSeq]),
				     true;
			     _ -> case State#state.are_we_dis of
				      true -> send_lsps([OurLSP], State);
				      _ -> ok
				  end,
				  false
			 end;
		    0 -> isis_lspdb:store_lsp(State#state.level, LSP),
			 isis_logger:warning("New LSP, storing..~n", []),
			 true;
		    _ -> false
		end,
	    case Announce of
		true -> flood_lsp(LSP, State);
		_ -> ok
	    end	    
    end,
    State.

handle_old_lsp(#isis_lsp{lsp_id = ID, tlv = TLVs,
			 sequence_number = SeqNo} = LSP, State) ->
    case isis_system:check_autoconf_collision(TLVs) of
	false ->
	    case isis_lspdb:lookup_lsps([ID], State#state.database) of
		[#isis_lsp{sequence_number = SN}] ->
		    case SeqNo > SN of
			true ->
			    <<_:6/binary, Node:8, Frag:8>> = ID,
			    isis_system:bump_lsp(State#state.level, Node, Frag, SeqNo);
			_ -> ok
		    end;
		_ ->
		    isis_logger:error("Purging an old LSP that claims to be from us: ~p",
				[ID]),
		    PLSP = LSP#isis_lsp{tlv = [],
					remaining_lifetime = 0,
					sequence_number = SeqNo + 1, checksum = 0,
					last_update = isis_protocol:current_timestamp()},
		    isis_lspdb:store_lsp(State#state.level, PLSP),
		    isis_lspdb:flood_lsp(State#state.level,
					 isis_system:list_interfaces(),
					 PLSP),
		    purged
	    end;
	_ -> ok
    end,
    State.

%%--------------------------------------------------------------------
%% @private
%% @doc
%%
%% Take the range from the CNSP packet and compare the LSP entries
%% with our database.
%%
%% @end
%%--------------------------------------------------------------------
-spec handle_csnp(isis_csnp(), tuple()) -> tuple().
handle_csnp(_, #state{database = DB} = State) when DB =:= undef ->
    State;
handle_csnp(#isis_csnp{start_lsp_id = Start,
		       end_lsp_id = End,
		       tlv = TLVs} = CSNP, State) ->
    %% Extract and create lsp_entry_detail records for the range from
    %% our datbase
    DB_LSPs = 
	lists:map(fun({ID, Seq, Check, Life}) ->
			  #isis_tlv_lsp_entry_detail{lifetime = Life,
						     lsp_id = ID,
						     sequence = Seq,
						     checksum = Check}
		  end,
		  isis_lspdb:range(Start, End, State#state.database)),

    %% Convert the CSNP TLVs into a single list of lsp_entry_details...
    CSNP_LSPs =
	lists:foldl(fun(F, Acc) ->
			    case is_record(F, isis_tlv_lsp_entry) of
				true -> Acc ++ F#isis_tlv_lsp_entry.lsps;
				_ -> Acc
			    end
		    end,
		    [], TLVs),

    %% Compare the 2 lists, to get our announce/request sets
    {Request, Announce} = compare_lsp_entries(DB_LSPs, CSNP_LSPs, {[], []}),
    announce_lsps(Announce, State),
    isis_logger:debug("CSNP on ~s: ~p", [State#state.interface_name, isis_logger:pr(CSNP, isis_protocol)]),
    isis_logger:debug("DB: ~p", [isis_logger:pr(DB_LSPs, isis_protocol)]),
    isis_logger:debug("Announce: ~p, Request: ~p", [Announce, Request]),
    NewState = update_ssn(Request, State),
    NewState.

%%--------------------------------------------------------------------
%% @private
%% @doc
%%
%% For now, we're just authenticating the IIH messages. Its trivial to
%% change the following to authenticate all messages.
%%
%% @end
%%--------------------------------------------------------------------
verify_authentication(#isis_iih{tlv = TLVs} = PDU, State) ->
    verify_authentication(TLVs, PDU, State);
verify_authentication(#isis_lsp{}, _State) ->
    valid;
verify_authentication(#isis_csnp{}, _State) ->
    valid;
verify_authentication(#isis_psnp{}, _State) ->
    valid.

verify_authentication(_, _, #state{authentication_type = none}) ->
    valid;
verify_authentication(TLVs, _PDU, #state{authentication_type = text,
					authentication_key = Key}) ->
   case isis_protocol:filter_tlvs(isis_tlv_authentication, TLVs) of
       [#isis_tlv_authentication{
	  type = text, signature = Key}] -> valid;
       [] -> missing_auth;
       _ -> invalid
   end;
verify_authentication(_, _, _) ->
    error.

authentication_tlv(State) ->    
    case State#state.authentication_type of
	none -> [];
	text -> [#isis_tlv_authentication{
		    type = text,
		    signature = State#state.authentication_key}];
	md5 -> [#isis_tlv_authentication{
		   type = md5,
		   %% Signature needs to be calculated later
		   signature = <<0:(16*8)>>}]
    end.

%%--------------------------------------------------------------------
%% @private
%% @doc
%%
%% Pass the PDU to be sent up to the interface, as that has the socket
%% and ability to send the frame.
%%
%% @end
%%--------------------------------------------------------------------
send_pdu(Type, PDU, PDU_Size, State) ->
    isis_interface:send_pdu(State#state.interface_ref, Type, 
			    PDU, PDU_Size,
			    State#state.level).

parse_args([{level, L} | T], State) ->
    parse_args(T, State#state{level = L});
parse_args([{snpa, M} | T], State) ->
    parse_args(T, State#state{snpa = M});
parse_args([{interface, N, I, M} | T], State) ->
    parse_args(T, State#state{interface_ref = I,
			      interface_name = N,
			      mtu = M});
parse_args([], State) ->
    State.

set_values([{encryption, Type, Key} | Vs], State) ->
    set_values(Vs, State#state{
		     authentication_type = Type,
		     authentication_key = Key});
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
    set_values(Vs, State#state{system_id = SID});
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
	     
	    

%%--------------------------------------------------------------------
%% @private
%% @doc
%%
%% Flood a received LSP to other interfaces. Ultimately, this needs to be
%% maintained in the LSPDB so if we learn an LSP via multiple paths within
%5 quick succession, we don't flood unnecessarily...
%%
%% @end
%%--------------------------------------------------------------------
flood_lsp(LSP, State) ->
    Is = isis_system:list_interfaces(),
    OutputIs = 
	lists:filter(
	  fun(#isis_interface{name = N})
		when N =:= State#state.interface_name ->
		  false;
	     (_) -> true
	  end, Is),
    isis_lspdb:flood_lsp(State#state.level, OutputIs, LSP).

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
		   [{authentication_type, text} | Fs],
		   #state{authentication_key = K} = State) ->
    io:format("isis_system:set_interface(\"~s\", ~s, [{encryption, ~s, ~p}]).~n",
	      [Name, Level, text, K]),
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
