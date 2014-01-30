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

-define(DEFAULT_INTERVAL, 10).
-define(SIOCGIFMTU, 16#8921).
-define(SIOCGIFHWADDR, 16#8927).
-define(SIOCADDMULTI, 16#8931).
-define(SIOCGIFINDEX, 16#8933).

%% API
-export([start_link/1, send_packet/2, stop/1,
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
	  hello_interval,  %% Hello interval
	  hold_time,       %% Hold time
	  timer,           %% Timer reference
	  adjacencies,     %% Dict for SNPA -> FSM pid
	  dis              %% DIS for this interface
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
init([{Name, Ref}]) ->
    {Socket, Mac, Ifindex, MTU, Port} = create_port(Name),
    Timer = erlang:start_timer((?DEFAULT_INTERVAL * 1000), self(), trigger),
    State = #state{name = Name, socket = Socket, port = Port,
		   mac = Mac, mtu = MTU,
		   ifindex = Ifindex, system_ref = Ref,
		   hello_interval = ?DEFAULT_INTERVAL,
		   hold_time = (3 * ?DEFAULT_INTERVAL),
		   timer = Timer, adjacencies = dict:new()},
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
handle_call({send_packet, _Packet}, _From, State) ->
    {reply, ok, State};

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
			 timer = TimerRef} = State) ->
    %% Cancel our timer
    case TimerRef of
	undef -> undef;
	_ ->
	    erlang:cancel_timer(TimerRef)
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

handle_info({timeout, _Ref, trigger}, State) ->
    erlang:cancel_timer(State#state.timer),
    send_iih(State),
    Timer = 
	erlang:start_timer(
	  isis_protocol:jitter((State#state.hello_interval * 1000),
			       ?ISIS_HELLO_JITTER),
	  self(), trigger),
    {noreply, State#state{timer = Timer}};

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
			L == 0, S == 0, C == 0
		end,
    Filtered = lists:filter(FilterFun, PSNP_LSPs),
    LSP_Ids = lists:map(fun(F) -> F#isis_tlv_lsp_entry_detail.lsp_id end, Filtered),
    LSPs = isis_lspdb:lookup_lsps(LSP_Ids, DBRef),
    send_lsps(LSPs, State),
    ok.
    

-spec handle_csnp(isis_csnp(), tuple()) -> ok | error.
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
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% 
%% Take 2 lists of isis_lsp_tlv_entry_details - the first from our
%% database, the second from the CSNP packet. We iterate the lists:
%%   If the LSP is on the first, but not the second, we need to announce
%%   If the LSP is on the second, but not eh first - we must request it
%%   If the LSP is on both, check the sequence number...
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
    lists:map(fun(LSP) ->
		      case isis_protocol:encode(LSP) of
			  {ok, Bin, Len} -> send_pdu(Bin, Len, State);
			  _ -> io:format("Failed to encode LSP ~p~n",
					 [LSP#isis_lsp.lsp_id])
		      end
	      end, LSPs),
    ok.

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
    State#state{adjacencies = NewAdjs};
handle_pdu(_From, #isis_lsp{} = LSP, State) ->
    LSP_Db = isis_system:lspdb(State#state.system_ref),
    isis_lspdb:store_lsp(LSP_Db, LSP),
    State;
handle_pdu(_From, #isis_csnp{} = CSNP, State) ->
    handle_csnp(CSNP, State),
    State;
handle_pdu(_From, #isis_psnp{} = PSNP, State) ->
    handle_psnp(PSNP, State),
    State;
handle_pdu(From, Pdu, State) ->
    io:format("Ignoring PDU from ~p~n~p~n", [From, Pdu]),
    State.

-spec set_values(list(), tuple()) -> tuple().
set_values([{mtu, Value} | T], State) when is_integer(Value) ->
    set_values(T, State#state{mtu = Value});
set_values([{hello_interval, Value} | T], State) ->
    set_values(T, State#state{hello_interval = Value});
set_values([{mac, Binary} | T], State) ->
    set_values(T, State#state{mac = Binary});
set_values([], State) ->
    State.

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

send_pdu(Pdu, Pdu_Size, State) ->
    Destination = <<1, 16#80, 16#C2, 0, 0, 16#15>>,
    Source = State#state.mac,
    Header = <<Destination/binary, Source/binary>>, 
    Len = Pdu_Size + 3,
    Packet = list_to_binary([Header, <<Len:16, 16#FE, 16#FE, 16#03>> | Pdu]),
    LL = create_sockaddr_ll(State#state.ifindex),
    Result = procket:sendto(State#state.socket, Packet, 0, LL),
    Result.

send_iih(State) ->
    IS_Neighbors =
	lists:map(fun({A, _}) -> A end,
		  dict:to_list(State#state.adjacencies)),
    ID = isis_system:system_id(State#state.system_ref),
    IIH = #isis_iih{
	     pdu_type = level2_iih,
	     circuit_type = level_1_2,
	     source_id = ID,
	     holding_time = State#state.hold_time,
	     priority = 10,
	     dis = <<255, 255, 0, 0, 3, 3, 0>>,
	     tlv =
		 [
		  #isis_tlv_is_neighbors{neighbors = IS_Neighbors},
		  #isis_tlv_area_address{areas = [<<73, 0, 2>>]},
		  #isis_tlv_protocols_supported{protocols = [ipv4, ipv6]},
		  #isis_tlv_ip_interface_address{addresses = [3232298904]}
		 ]},
    {ok, PDU, PDU_Size} = isis_protocol:encode(IIH),
    send_pdu(PDU, PDU_Size, State).

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
