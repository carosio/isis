%%%-------------------------------------------------------------------
%%% @author Rick Payne <rickp@rossfell.co.uk>
%%% @copyright (C) 2014, Rick Payne
%%% @doc
%%%
%%% @end
%%% Created : 18 Jan 2014 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------
-module(isis_interface).

-behaviour(gen_server).

-include("isis_protocol.hrl").

-define(DEFAULT_HELLO_INTERVAL, 10).
-define(SIOCGIFMTU, 16#8921).
-define(SIOCGIFHWADDR, 16#8927).
-define(SIOCADDMULTI, 16#8931).
-define(SIOCGIFINDEX, 16#8933).

%% API
-export([start_link/1, send_packet/2, send_hello/1, stop/1,
	 get_state/2, get_state/1, set/2]).

%% Debug export
-export([]).
-compile(export_all).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE).
-define(ETH_P_802_2, 16#0400).

-record(state, {
	  name,            %% Interface name
	  ifindex,         %% Interface ifindex
	  socket,          %% Procket socket...
	  port,            %% Erlang port handling socket
	  system_ref,      %% Our 'IS-IS'
	  mac,             %% This interface's MAC address
	  mtu,             %% Interface MTU
	  hello_interval = ?DEFAULT_HELLO_INTERVAL,
	  hold_time = (3 * ?DEFAULT_HELLO_INTERVAL),
	  iih_timer,       %% Timer reference
	  ssn_timer,       %% SSN timer
	  adjacencies,     %% Dict for SNPA -> FSM pid
	  priority = 0,    %% 0 - 127 (6 bit) for our priority, highest wins
	  dis,             %% Current DIS for this interface ( 7 bytes, S-id + pseudonode)
	  dis_priority,    %% Current DIS's priority
	  are_we_dis = false,  %% True if we're the DIS
	  circuit_type,    %% Level-1 or level-1-2 (just level-2 is invalid)
	  %%srm,             %% 'Send Routing Message' - list of LSPs to announce
	  ssn              %% 'Send Seq No' - list of LSPs to include in next PSNP
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
send_packet(Pid, Packet) ->
    gen_server:call(Pid, {send_packet, Packet}).

send_hello(Pid) ->
    gen_sever:call(Pid, {send_iih}).

stop(Pid) ->
    gen_server:cast(Pid, stop).

get_state(Pid, Item) ->
    gen_server:call(Pid, {get_state, Item}).

get_state(Pid) ->
    gen_server:call(Pid, {get_state}).

set(Pid, Values) ->
    gen_server:call(Pid, {set, Values}).

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
    Timer = erlang:start_timer((?DEFAULT_HELLO_INTERVAL * 1000), self(), iih),
    State = extract_args(Args, #state{}),
    {Socket, Mac, Ifindex, MTU, Port} = create_port(State#state.name),
    StartState = State#state{socket = Socket, port = Port,
			     mac = Mac, mtu = MTU,
			     ifindex = Ifindex, iih_timer = Timer,
			     adjacencies = dict:new(),
			     ssn_timer = undef, ssn = []},
    {ok, StartState}.

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
handle_call({send_packet, _Packet}, _From, State) ->
    {reply, ok, State};

handle_call({send_iih}, _From, State) ->
    send_iih(State),
    {reply,ok, State};

handle_call({get_state, mac}, _From, State) ->
    {reply, State#state.mac, State};
handle_call({get_state, mtu}, _From, State) ->
    {reply, State#state.mtu, State};
handle_call({get_state, hello_interval}, _From, State) ->
    {reply, State#state.hello_interval, State};
handle_call({get_state, hold_time}, _From, State) ->
    {reply, State#state.hold_time, State};

handle_call({get_state}, _From, State) ->
    {reply, State, State};

handle_call({set, Values}, _From, State) ->
    NewState = set_values(Values, State),
    {reply, ok, NewState};

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
handle_cast(stop, #state{port = Port,
			 adjacencies = Adjs,
			 iih_timer = IIHTimerRef,
			 ssn_timer = SSNTimerRef} = State) ->
    %% Cancel our timer
    case IIHTimerRef of
	undef -> undef;
	_ -> erlang:cancel_timer(IIHTimerRef)
    end,
    case SSNTimerRef of
	undef -> undef;
	_ -> erlang:cancel_timer(SSNTimerRef)
    end,
    %% Close down the port (does this close the socket?)
    erlang:port_close(Port),
    %% Notify our adjacencies
    dict:map(fun(_Key, Pid) -> gen_fsm:send_event(Pid, stop) end,
	     Adjs),
    {stop, normal, State};

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
handle_info({_port, {data,
		     <<_To:6/binary, From:6/binary, _Len:16,
		       16#FE:8, 16#FE:8, 3:8, PDU/binary>>}},
	    State) ->
    NewState = 
	case isis_protocol:decode(PDU) of
	    {ok, DecodedPDU} ->
		handle_pdu(From, DecodedPDU, State);
	    _ ->
		io:format("Failed to decode: ~p~n", [PDU]),
		State
	end,
    {noreply, NewState};

handle_info({_port, {data, _}}, State) ->
    {noreply, State};

handle_info({timeout, _Ref, iih}, State) ->
    erlang:cancel_timer(State#state.iih_timer),
    send_iih(State),
    Timer = 
	erlang:start_timer(
	  isis_protocol:jitter((State#state.hello_interval * 1000),
			       ?ISIS_HELLO_JITTER),
	  self(), iih),
    {noreply, State#state{iih_timer = Timer}};

handle_info({timeout, _Ref, ssn}, State) ->
    erlang:cancel_timer(State#state.ssn_timer),
    NewState = send_psnp(State#state{ssn_timer = undef}),
    {noreply, NewState};

handle_info(Info, State) ->
    io:format("Unknown message: ~p", [Info]),
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
%% A PSNP is either ack-ing an LSP we've sent, or its requesting
%% specific LSPs. So if the sequence number is set, then we should
%% send the LSP. Otherwise, there's nothing to do.
%%
%% @end
%%--------------------------------------------------------------------

-spec handle_psnp(isis_psnp(), tuple()) -> ok | error.
handle_psnp(#isis_psnp{tlv = TLVs}, State) ->
    %% Extract and create lsp_entry_detail records for the range from
    %% our datbase
    DBPid = isis_system:lspdb(State#state.system_ref),
    DBRef = isis_lspdb:get_db(DBPid),
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
    LSPs = isis_lspdb:lookup_lsps(LSP_Ids, DBRef),
    send_lsps(LSPs, State),
    ok.

-spec handle_lsp(isis_lsp(), tuple()) -> tuple().
handle_lsp(#isis_lsp{lsp_id = ID, sequence_number = TheirSeq} = LSP, State) ->
    DBPid = isis_system:lspdb(State#state.system_ref),
    DBRef = isis_lspdb:get_db(DBPid),
    L = isis_lspdb:lookup_lsps([ID], DBRef),
    case length(L) of
	1 -> [OurLSP] = L,
	     OurSeq = OurLSP#isis_lsp.sequence_number,
	     case OurSeq < TheirSeq of
		 true -> isis_lspdb:store_lsp(DBPid, LSP);
		 _ -> ok
	     end;
	0 -> isis_lspdb:store_lsp(DBPid, LSP);
	_ -> ok
    end,
    State.

-spec handle_csnp(isis_csnp(), tuple()) -> tuple().
handle_csnp(#isis_csnp{start_lsp_id = Start,
		       end_lsp_id = End,
		       tlv = TLVs}, State) ->
    %% Extract and create lsp_entry_detail records for the range from
    %% our datbase
    DBPid = isis_system:lspdb(State#state.system_ref),
    DBRef = isis_lspdb:get_db(DBPid),
    DB_LSPs = 
	lists:map(fun({ID, Seq, Check, Life, _TS}) ->
			  #isis_tlv_lsp_entry_detail{lifetime = Life,
						     lsp_id = ID,
						     sequence = Seq,
						     checksum = Check}
		  end,
		  isis_lspdb:range(Start, End, DBRef)),

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
    DBPid = isis_system:lspdb(State#state.system_ref),
    DBRef = isis_lspdb:get_db(DBPid),
    LSPs = isis_lspdb:lookup_lsps(lists:sort(IDs), DBRef),
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
	    undef -> erlang:start_timer(isis_protocol:jitter(?ISIS_PSNP_TIMER,
							     ?ISIS_PSNP_JITTER),
					self(), ssn);
	    _ -> State#state.ssn_timer
	end,
    State#state{ssn = SSN ++ LSP_Ids, ssn_timer = Timer}.

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
send_psnp(#state{system_ref = Ref, ssn = SSN} = State) ->
    SID = isis_system:system_id(Ref),
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
%% Handle the various PDUs that we can receive on this interface
%%
%% @end
%%--------------------------------------------------------------------
-spec handle_pdu(binary(), isis_pdu(), tuple()) -> tuple().
handle_pdu(From, #isis_iih{} = IIH,
	   #state{adjacencies = Adjs} = State) ->
    NewAdjs = 
	case dict:find(From, Adjs) of
	    {ok, Pid} ->
		gen_fsm:send_event(Pid, {iih, IIH}),
		Adjs;
	    _ ->
		{ok, NewPid} = isis_adjacency:start_link([{neighbor, From},
							  {snpa, State#state.mac},
							  {interface, self()}]),
		gen_fsm:send_event(NewPid, {iih, IIH}),
		dict:store(From, NewPid, Adjs)
	end,
    AdjState = State#state{adjacencies = NewAdjs},
    handle_dis_election(IIH, AdjState);
handle_pdu(_From, #isis_lsp{} = LSP, State) ->
    handle_lsp(LSP, State);
handle_pdu(_From, #isis_csnp{} = CSNP, State) ->
    handle_csnp(CSNP, State);
handle_pdu(_From, #isis_psnp{} = PSNP, State) ->
    handle_psnp(PSNP, State),
    State;
handle_pdu(From, Pdu, State) ->
    io:format("Ignoring PDU from ~p~n~p~n", [From, Pdu]),
    State.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% 
%%
%%
%% @end
%%--------------------------------------------------------------------
-spec set_values(list(), tuple()) -> tuple().
set_values([{mtu, Value} | T], State) when is_integer(Value) ->
    set_values(T, State#state{mtu = Value});
set_values([{hello_interval, Value} | T], State) ->
    set_values(T, State#state{hello_interval = Value});
set_values([{mac, Binary} | T], State) ->
    set_values(T, State#state{mac = Binary});
set_values([{priority, Value} | T], State) when is_integer(Value) ->
    set_values(T, State#state{priority = Value});
set_values([], State) ->
    State.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% 
%%
%%
%% @end
%%--------------------------------------------------------------------

-spec create_port(string()) -> {integer(), binary(), integer(), integer(), port()} | error.
create_port(Name) ->
    {ok, S} = procket:open(0,
			   [{progname, "sudo /usr/local/bin/procket"},
			    {family, packet},
			    {type, raw},
			    {protocol, ?ETH_P_802_2}]),
    {Ifindex, Mac, MTU} = interface_details(S, Name),
    LL = create_sockaddr_ll(Ifindex),
    ok = procket:bind(S, LL),
    Port = erlang:open_port({fd, S, S}, [binary, stream]),
    {S, Mac, Ifindex, MTU, Port}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% 
%%
%%
%% @end
%%--------------------------------------------------------------------
send_pdu(Pdu, Pdu_Size, State) ->
    Destination = <<1, 16#80, 16#C2, 0, 0, 16#15>>,
    Source = State#state.mac,
    Header = <<Destination/binary, Source/binary>>, 
    Len = Pdu_Size + 3,
    Packet = list_to_binary([Header, <<Len:16, 16#FE, 16#FE, 16#03>> | Pdu]),
    LL = create_sockaddr_ll(State#state.ifindex),
    Result = procket:sendto(State#state.socket, Packet, 0, LL),
    Result.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% 
%%
%%
%% @end
%%--------------------------------------------------------------------
send_iih(State) ->
    IS_Neighbors =
	lists:map(fun({A, _}) -> A end,
		  dict:to_list(State#state.adjacencies)),
    ID = isis_system:system_id(State#state.system_ref),
    Areas = isis_system:areas(State#state.system_ref),
    IIH = #isis_iih{
	     pdu_type = level2_iih,
	     circuit_type = State#state.circuit_type,
	     source_id = ID,
	     holding_time = State#state.hold_time,
	     priority = State#state.priority,
	     dis = State#state.dis,
	     tlv =
		 [
		  #isis_tlv_is_neighbors{neighbors = IS_Neighbors},

		  %% Need to get these from the 'system' eventually...
		  #isis_tlv_area_address{areas = Areas},
		  #isis_tlv_protocols_supported{protocols = [ipv4, ipv6]},
		  #isis_tlv_ip_interface_address{addresses = [3232298904]}
		 ]},
    {ok, PDU, PDU_Size} = isis_protocol:encode(IIH),
    send_pdu(PDU, PDU_Size, State).

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

    ID = isis_system:system_id(State#state.system_ref),
    DIS = <<ID:6/binary, Node:8>>,
    NewState = State#state{dis = DIS, are_we_dis = true},
    send_iih(NewState),
    NewState.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% 
%%
%%
%% @end
%%--------------------------------------------------------------------
-spec create_sockaddr_ll(integer()) -> binary().
create_sockaddr_ll(Ifindex) ->
    Family = procket:family(packet),
    <<Family:16/native, ?ETH_P_802_2:16/native, Ifindex:32/native,
      0:16, 0:8, 0:8, 0:8/unit:8>>.

%%
%% Linux specific, be nice to get this in the
%% procket module...
%%
interface_details(Socket, Name) ->
    N = list_to_binary(Name),
    Req = <<N/binary, 0:(8*(40 - byte_size(N)))>>,
    case procket:ioctl(Socket, ?SIOCGIFHWADDR, Req) of
	{error, _} -> error;
	{ok, Mac_Response} -> 
	    {ok, Ifindex_Response} = procket:ioctl(Socket,
						   ?SIOCGIFINDEX, Req),
	    {ok, MTU_Response} = procket:ioctl(Socket,
					       ?SIOCGIFMTU, Req),
	    <<_:16/binary, I:32/native, _/binary>> = Ifindex_Response,
	    <<_:18/binary, Mac:6/binary, _/binary>> = Mac_Response,
	    <<_:16/binary, MTU:16/native, _/binary>> = MTU_Response,
	    %% Req2 = <<N/binary, 0:(8*(16 - byte_size(N))), I:16/native,
	    %%  	     16#01, 16#80, 16#c2, 0, 0, 16#14, 0:128>>,
	    %% Req3 = <<N/binary, 0:(8*(16 - byte_size(N))), I:16/native,
	    %%  	     16#01, 16#80, 16#c2, 0, 0, 16#15, 0:128>>,
	    %% {ok, _} = procket:ioctl(Socket, ?SIOCADDMULTI, Req2),
	    %% {ok, _} = procket:ioctl(Socket, ?SIOCADDMULTI, Req3),
	    {I, Mac, MTU}
    end.

extract_args([{name, Name} | T], State) ->
    extract_args(T, State#state{name = Name});
extract_args([{system_ref, Ref} | T], State) ->
    extract_args(T, State#state{system_ref = Ref});
extract_args([{circuit_type, Type} | T] , State) ->
    extract_args(T, State#state{circuit_type = Type});
extract_args([{hello_interval, T} | T], State) ->
    extract_args(T, State#state{hello_interval = T});
extract_args([], State) ->
    State.
