%%%-------------------------------------------------------------------
%%% @author Rick Payne <rickp@rossfell.co.uk>
%%% @copyright (C) 2014, Rick Payne
%%% @doc
%%%
%%% Handle an IS-IS level for a given interface.
%%%
%%% @end
%%% Created :  7 Feb 2014 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------
-module(isis_interface_level).

-behaviour(gen_server).

-include("isis_protocol.hrl").

%% API
-export([start_link/1, get_state/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3,
	 handle_pdu/3, stop/1]).

-define(SERVER, ?MODULE).

-record(state, {
	  level,           %% The level
	  interface_ref,   %% Interface
	  snpa,            %% Our mac address
	  database = undef, %% The LSPDB reference
	  hello_interval = (?DEFAULT_HOLD_TIME / 3),
	  hold_time = ?DEFAULT_HOLD_TIME,
	  iih_timer = undef :: reference() | undef, %% iih timer for this level
	  ssn_timer = undef :: reference() | undef, %% SSN timer
	  adjacencies,     %% Dict for SNPA -> FSM pid
	  priority = 0,    %% 0 - 127 (6 bit) for our priority, highest wins
	  dis,             %% Current DIS for this interface ( 7 bytes, S-id + pseudonode)
	  dis_priority,    %% Current DIS's priority
	  are_we_dis = false,  %% True if we're the DIS
	  dis_continuation = undef,%% Do we have more CSNP's to send?
	  dis_timer = undef :: reference() | undef, %% If we're DIS, we use this timer to announce CSNPs
	  ssn = [] :: [binary()]  %% list of pending

	 }).

%%%===================================================================
%%% API
%%%===================================================================
handle_pdu(Pid, From, PDU) ->
    gen_server:cast(Pid, {received, From, PDU}).

get_state(Pid, Item) ->
    gen_server:call(Pid, {get_state, Item}).

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
			       adjacencies = dict:new()
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

handle_call({get_state, hello_interval}, _From, State) ->
    {reply, State#state.hello_interval, State};
handle_call({get_state, hold_time}, _From, State) ->
    {reply, State#state.hold_time, State};

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
handle_cast(stop, #state{adjacencies = Adjs,
			 iih_timer = IIHTimerRef,
			 ssn_timer = SSNTimerRef,
			 dis_timer = DISTimerRef} = State) ->
    %% Cancel our timer
    cancel_timers([IIHTimerRef, SSNTimerRef, DISTimerRef]),
    %% Notify our adjacencies
    dict:map(fun(_Key, Pid) -> gen_fsm:send_event(Pid, stop) end,
	     Adjs),
    {stop, normal, State};

handle_cast({received, From, PDU}, State) ->
    NewState = process_pdu(From, PDU, State),
    {noreply, NewState};


handle_cast({set_database}, State) ->
    DB = isis_lspdb:get_db(State#state.level),
    Timer = start_timer(iih, State),
    {noreply, State#state{database = DB, iih_timer = Timer}};

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

handle_info({timeout, _Ref, dis}, State) ->
    cancel_timers([State#state.ssn_timer]),
    NewState = send_csnp(State),
    Timer = start_timer(dis, NewState),
    {noreply, NewState#state{dis_timer = Timer}};

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
handle_iih(From, IIH, #state{adjacencies = Adjs} = State) ->
    NewAdjs = 
	case dict:find(From, Adjs) of
	    {ok, Pid} ->
		gen_fsm:send_event(Pid, {iih, IIH}),
		Adjs;
	    _ ->
		{ok, NewPid} = isis_adjacency:start_link([{neighbor, From},
							  {snpa, State#state.snpa},
							  {level, IIH#isis_iih.pdu_type},
							  {level_pid, self()}]),
		erlang:monitor(process, NewPid),
		gen_fsm:send_event(NewPid, {iih, IIH}),
		dict:store(From, NewPid, Adjs)
	end,
    AdjState = State#state{adjacencies = NewAdjs},
    DISState = handle_dis_election(IIH, AdjState),
    DISState.

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
-spec handle_dis_election(isis_iih(), tuple()) -> tuple().
handle_dis_election(#isis_iih{priority = TheirP, dis = DIS, source_id = SID},
		    #state{priority = OurP} = State)
  when TheirP > OurP ->   %% ; TheirP == OurP, TheirSNPA > OurMac
    <<D:6/binary, _:1/binary>> = DIS,
    DIS_Priority = 
	case D == SID of
	    true -> TheirP;
	    _ -> State#state.dis_priority
	end,
    State#state{dis = DIS, dis_priority = DIS_Priority};
handle_dis_election(#isis_iih{priority = TheirP, dis = DIS, source_id = SID},
		    #state{priority = OurP} = State)
  when TheirP < OurP ->
    <<D:6/binary, D1:1/binary>> = DIS,
    NewState = 
	case dict:find(D, State#state.adjacencies) of
	    {ok, _} -> State;
	    _ -> assume_dis(State)
	end,
    NewState.

assume_dis(State) ->
    %% Get pseudo-node here, create LSP etc..
    Node = 2,

    DIS_Timer = start_timer(dis, State),

    ID = isis_system:system_id(),
    DIS = <<ID:6/binary, Node:8>>,
    NewState = State#state{dis = DIS, dis_timer = DIS_Timer,
			   are_we_dis = true},
    send_iih(NewState),
    NewState.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% 
%% Send an IIH message
%%
%% @end
%%--------------------------------------------------------------------
send_iih(State) ->
    IS_Neighbors =
	lists:map(fun({A, _}) -> A end,
		  dict:to_list(State#state.adjacencies)),
    ID = isis_system:system_id(),
    Areas = isis_system:areas(),
    Circuit = 
	case State#state.level of
	    level_1 -> level_1;
	    level_2 -> level_1_2
	end,
    IIH = #isis_iih{
	     pdu_type = level2_iih,
	     circuit_type = Circuit,
	     source_id = ID,
	     holding_time = erlang:trunc(State#state.hold_time / 1000),
	     priority = State#state.priority,
	     dis = State#state.dis,
	     tlv =
		 [
		  #isis_tlv_is_neighbors{neighbors = IS_Neighbors},

		  #isis_tlv_area_address{areas = Areas},

		  %% Need to get these from the 'system' eventually...
		  #isis_tlv_protocols_supported{protocols = [ipv4, ipv6]},
		  #isis_tlv_ip_interface_address{addresses = [3232298904]}
		 ]},
    {ok, PDU, PDU_Size} = isis_protocol:encode(IIH),
    send_pdu(PDU, PDU_Size, State).

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
    generate_csnp(Args, 90, Summary, State),
    NextDC = 
	case Continue of
	    '$end_of_table' -> undef;
	    _ -> Continue
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

generate_csnp({Status, _}, Chunk_Size, Summary, State) ->
    Sys_ID = isis_system:system_id(),
    Source = <<Sys_ID:6/binary, 0:8>>,
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
				#isis_tlv_lsp_entry_detail{lsp_id = ID,
							   sequence = Seq,
							   checksum = Check,
							   lifetime = Lifetime}
			end, Summary),
    DetailPackageFun = fun(F) -> [#isis_tlv_lsp_entry{lsps = F}] end,
    TLVs = isis_protocol:package_tlvs(Details, DetailPackageFun,
				      ?LSP_ENTRY_DETAIL_PER_TLV),
    CSNP = #isis_csnp{pdu_type = level2_csnp,
		      source_id = Source,
		      start_lsp_id = Start,
		      end_lsp_id = End,
		      tlv = TLVs},
    {ok, PDU, PDU_Size} = isis_protocol:encode(CSNP),
    send_pdu(PDU, PDU_Size, State),
    ok.

-spec process_pdu(binary(), isis_pdu(), tuple()) -> tuple().
process_pdu(From, #isis_iih{} = IIH, State) ->
    handle_iih(From, IIH, State);
process_pdu(_From, #isis_lsp{} = LSP, State) ->
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
start_timer(dis, #state{dis_continuation = DC}) when DC == undef ->
    erlang:start_timer(isis_protocol:jitter(?ISIS_CSNP_TIMER, ?ISIS_CSNP_JITTER),
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
    AliveLSPs = lists:filter(fun isis_protocol:filter_lifetime/1, LSPs),
    send_lsps(AliveLSPs, State),
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
    lists:map(fun(L) -> case isis_protocol:encode(L) of
			    {ok, Bin, Len} -> send_pdu(Bin, Len, State);
			    _ -> io:format("Failed to encode LSP ~p~n",
					   [L#isis_lsp.lsp_id])
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
    SID = isis_system:system_id(),
    Source = <<SID:6/binary, 0:8>>,
    TLVs = 
	lists:map(fun(LSP) -> #isis_tlv_lsp_entry_detail{lsp_id = LSP} end,
		  SSN),

    DetailPackageFun = fun(F) -> [#isis_tlv_lsp_entry{lsps = F}] end,			 
    TLVPackageFun = fun(F) -> [#isis_psnp{pdu_type = level2_psnp,
					  source_id = Source,
					  tlv = F}]
		    end,

    %% Now we have the detail entries we need to bundle up as many
    %% entries as can be fitted into the 255 byte TLV limit and then
    %% as many TLVs as can be fitted into a messgae (based on MTU).
    List_of_TLVs = isis_protocol:package_tlvs(TLVs, DetailPackageFun,
					      ?LSP_ENTRY_DETAIL_PER_TLV),
    List_of_PDUs = isis_protocol:package_tlvs(List_of_TLVs, TLVPackageFun,
					      ?LSP_ENTRY_PER_PDU),
    %%% ....
    lists:map(fun(F) ->
		      case isis_protocol:encode(F) of
			  {ok, Bin, Len} -> send_pdu(Bin, Len, State);
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
    FilterFun = fun(#isis_tlv_lsp_entry_detail{lifetime = L, sequence = S, checksum = C}) ->
			(L == 0) and (S == 0) and (C == 0)
		end,
    Filtered = lists:filter(FilterFun, PSNP_LSPs),
    LSP_Ids = lists:map(fun(F) -> F#isis_tlv_lsp_entry_detail.lsp_id end, Filtered),
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
handle_lsp(#isis_lsp{lsp_id = ID, sequence_number = TheirSeq} = LSP, State) ->
    <<RemoteSys:6/binary, _Rest/binary>> = ID,
    case RemoteSys =:= isis_system:system_id() of
	true -> handle_old_lsp(LSP, State);
	_ ->
	    L = isis_lspdb:lookup_lsps([ID], State#state.database),
	    case length(L) of
		1 -> [OurLSP] = L,
		     OurSeq = OurLSP#isis_lsp.sequence_number,
		     case OurSeq =< TheirSeq of
			 true -> isis_lspdb:store_lsp(State#state.level, LSP);
			 _ -> ok
		     end;
		0 -> isis_lspdb:store_lsp(State#state.level, LSP);
		_ -> ok
	    end
    end,
    State.

handle_old_lsp(#isis_lsp{lsp_id = ID} = LSP, State) ->
    [OurLSP] = isis_lspdb:lookup_lsps([ID], State#state.database),
    isis_lspdb:store_lsp(State#state.level, OurLSP#isis_lsp{
					      sequence_number = (LSP#isis_lsp.sequence_number + 1)
					     }),
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
		       tlv = TLVs}, State) ->
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
    NewState = update_ssn(Request, State),
    NewState.

%%--------------------------------------------------------------------
%% @private
%% @doc
%%
%% Pass the PDU to be sent up to the interface, as that has the socket
%% and ability to send the frame.
%%
%% @end
%%--------------------------------------------------------------------
send_pdu(PDU, PDU_Size, State) ->
    isis_interface:send_pdu(State#state.interface_ref, PDU, PDU_Size,
			    State#state.level).

parse_args([{level, L} | T], State) ->
    parse_args(T, State#state{level = L});
parse_args([{snpa, M} | T], State) ->
    parse_args(T, State#state{snpa = M});
parse_args([{interface, I} | T], State) ->
    parse_args(T, State#state{interface_ref = I});
parse_args([], State) ->
    State.
