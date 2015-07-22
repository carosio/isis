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
%%% Created : 05 Jul 2015 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------
-module(isis_interface_p2mp).

-behaviour(gen_server).

-include("isis_system.hrl").
-include("isis_protocol.hrl").
-include("isis_interface_lib.hrl").

%% API
-export([start_link/1,
	 handle_pdu/2,
	 send_pdu/5,
	 set/3,
	 get/2,
	 update_metric/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE).

-record(state, {
	  from,          %% Address/Details of who is the other end of this p2p link
	  neighbor = undef, %% SID of neighbor
	  mode,          %% point_to_multipoint
	  interface_name,%% Name of interface (for address lookups)
	  interface_mod, %% Module handling I/O
	  interface_pid, %% Pid of instance
	  level = level_1,
	  system_id = undefined,
	  hello_interval = (?DEFAULT_HOLD_TIME / 3),
	  hold_time = ?DEFAULT_HOLD_TIME,
	  hold_timer = undef :: reference() | undef, %% hold timer
	  csnp_timer = undef :: reference() | undef, %% csnp timer
	  csnp_interval = ?ISIS_P2P_CSNP_TIMER,
	  metric = ?DEFAULT_METRIC,
	  metric_type = wide :: wide | narrow,
	  padding = true :: true | false,  %% To pad or not...
	  iih_timer = undef :: reference() | undef, %% iih timer for this level
	  ip_addresses = [],
	  ipv6_addresses = [],
	  pdu_state = #isis_pdu_state{}
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
start_link(Args) ->
    gen_server:start_link(?MODULE, Args, []).

handle_pdu(Pid, PDU) ->
    gen_server:cast(Pid, {handle_pdu, PDU}).

send_pdu(Pid, Type, PDU, PDU_Size, Level) ->
    gen_server:cast(Pid, {send_pdu, Type, PDU, PDU_Size, Level}).

set(Pid, level_1, Args) ->
    gen_server:call(Pid, {set, level_1, Args});
set(_Pid, _Level, _Args) ->
    not_supported_yet.

get(Pid, neighbor) ->
    gen_server:call(Pid, {get_state, neighbor}).

update_metric(Pid) ->
    gen_server:cast(Pid, {update_metric}).


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
    State = extract_args(Args, #state{}),
    IIHTimer = start_timer(iih, State),
    CSNPTimer = start_timer(csnp, State),
    HOLDTimer = start_timer(hold, State),
    isis_system:add_circuit(#isis_circuit{
			       name = State#state.from,
			       module = ?MODULE,
			       id = self(),
			       parent_interface = State#state.interface_name}),
    gen_server:cast(self(), {setup_pdu}),
    {ok, State#state{iih_timer = IIHTimer,
		     hold_timer = HOLDTimer,
		     csnp_timer = CSNPTimer}}.

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
handle_call({set, _Level, Args}, _From, State) ->
    {reply, ok, set_values(Args, State)};
handle_call({get_state, neighbor}, _From, State) ->
    {reply, State#state.neighbor, State};
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
handle_cast({setup_pdu}, State) ->
    SID = isis_system:system_id(),
    DB = isis_lspdb:get_db(level_1),
    PDUState = #isis_pdu_state{
		  parent = isis_interface_p2mp,
		  parent_pid = self(),
		  interface_name = State#state.interface_name,
		  circuit_name = {ipv6, State#state.from},
		  system_id = SID,
		  level = level_1,
		  authentication = isis_config:get_item([{interface, State#state.interface_name},
							 {level, level_1}], authentication),
		  level_authentication = isis_config:get_item([{interface, State#state.interface_name},
							       {level, level_1}], level_authentication),
		  database = DB
		 },
    {noreply, State#state{pdu_state = PDUState}};
handle_cast({handle_pdu, PDU}, State) ->
    {noreply, handle_p2mp_pdu(PDU, State)};
handle_cast({send_pdu, Type, PDU, PDU_Size, _Level}, State) ->
    do_send_pdu(Type, PDU, PDU_Size, State),
    {noreply, State};
handle_cast({update_metric}, State) ->
    Metric = isis_config:get_item(
	       [{interface, State#state.interface_name},
		{level, level_1},
		{neighbor, State#state.from}],
	       metric),
    case State#state.neighbor of
	undef -> ok;
	N ->
	    do_update_reachability_tlv(add, <<N:6/binary, 0:8>>, 0, Metric, State)
    end,
    {noreply, State};
handle_cast(stop, #state{iih_timer = IIHT,
			 pdu_state = Pdu} = State) ->
    %% Cancel our timer
    cancel_timers([IIHT, Pdu#isis_pdu_state.ssn_timer]),
    {stop, normal, State}.



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
    %% Refresh our config...
    RefreshState =
	set_values(
	  isis_config:get([{interface, State#state.interface_name}, {level, level_1}]),
	  State),
    RefreshState2 = 
	set_values(
	  isis_config:get([{interface, State#state.interface_name}, {level, level_1},
			   {neighbor, State#state.from}]),
	  RefreshState),
    send_iih(RefreshState2),
    Timer = start_timer(iih, RefreshState2),
    {noreply, RefreshState2#state{iih_timer = Timer}};
handle_info({timeout, _Ref, csnp}, #state{pdu_state = Pdu} = State) ->
    NewPdu = isis_interface_lib:send_csnp(Pdu#isis_pdu_state{ssn_timer = undef}),
    Timer = start_timer(csnp, State),
    {noreply, State#state{pdu_state = NewPdu, csnp_timer = Timer}};
handle_info({timeout, _Ref, ssn}, #state{pdu_state = Pdu} = State) ->
    NewPdu = isis_interface_lib:send_psnp(Pdu#isis_pdu_state{ssn_timer = undef}),
    {noreply, State#state{pdu_state = NewPdu}};
handle_info({timeout, _Ref, hold}, State) ->
    isis_system:delete_all_sid_addresses(self()),
    {stop, normal, State};
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
terminate(_Reason, State) ->
    isis_logger:error("Stopping!"),
    isis_system:delete_all_sid_addresses(self()),
    stopping(State),
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
send_iih(#state{system_id = SID}) when SID =:= undefined; byte_size(SID) =/= 6 ->
    no_system_id;
send_iih(#state{system_id = SID,
		pdu_state = Pdu} = State) ->
    Areas = isis_system:areas(),
    V4Addresses = get_addresses(State, ipv4),
    V6Addresses = 
	lists:sublist(lists:filter(fun(A) -> <<LL:16, _R:112>> = <<A:128>>, LL =:= 16#FE80 end,
				   get_addresses(State, ipv6)),
		     ?ISIS_IIH_IPV6COUNT),
    ISNeighborsTLV =
	case State#state.neighbor of
	    undef -> [];
	    N -> [#isis_tlv_is_neighbors{neighbors = [N]}]
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
    IIH = #isis_p2p_iih{
	     pdu_type = p2p_iih,
	     circuit_type = level_1,
	     source_id = SID,
	     holding_time = 30,
	     local_circuit_id = 1,
	     tlv = TLVs
	},
    {ok, _, PDU_Size} = isis_protocol:encode(IIH, Pdu#isis_pdu_state.authentication),
    PadTLVs = generate_padding(get_mtu(State) - PDU_Size -3,
			       State),
    ActualIIH = IIH#isis_p2p_iih{tlv = TLVs ++ PadTLVs},
    {ok, SendPDU, SendPDU_Size} = isis_protocol:encode(ActualIIH, Pdu#isis_pdu_state.authentication),
    do_send_pdu(p2p_iih, SendPDU, SendPDU_Size, State).

%% Send a PDU, called via flood_lsp amoungst others..
do_send_pdu(_Type, PDU, PDU_Size, #state{interface_mod = IM,
					 interface_pid = PID,
					 from = From}) ->
    IM:send_pdu_to(PID, From,
		   PDU, PDU_Size).

handle_p2mp_pdu(#isis_p2p_iih{} = IIH, State) ->
    isis_logger:debug("Handling p2p iih from ~p", [IIH#isis_p2p_iih.source_id]),
    cancel_timers([State#state.hold_timer]),
    NewState = 
	case IIH#isis_p2p_iih.source_id =:= State#state.neighbor of
	    true -> State;
	    false ->
		isis_logger:debug("Updating our reachability tlv"),
		N = IIH#isis_p2p_iih.source_id,
		do_update_reachability_tlv(add, <<N:6/binary, 0:8>>, 0, State#state.metric, State),
		State#state{neighbor = N}
	end,
    NewState2 = verify_interface_addresses(IIH, NewState),
    HoldTimer = start_timer(hold, NewState),
    NewState2#state{hold_timer = HoldTimer};
handle_p2mp_pdu(#isis_lsp{} = LSP, #state{pdu_state = PDU} = State) ->
    <<SID:6/binary, _:16>> = LSP#isis_lsp.lsp_id,
    isis_logger:debug("Handling LSP from ~p: ~p",
		      [isis_system:lookup_name(SID), LSP]),
    isis_interface_lib:handle_lsp(LSP, PDU),
    State;
handle_p2mp_pdu(#isis_csnp{} = CSNP, #state{pdu_state = PDU} = State) ->
    isis_logger:debug("Processing CSNP"),
    NewPDU = isis_interface_lib:handle_csnp(CSNP, PDU),
    State#state{pdu_state = NewPDU};
handle_p2mp_pdu(#isis_psnp{} = PSNP, #state{pdu_state = PDU} = State) ->
    isis_logger:debug("Processing PSNP"),
    isis_interface_lib:handle_psnp(PSNP, PDU),
    State;
handle_p2mp_pdu(Pdu, State) ->
    isis_logger:warning("Ignoring PDU: ~p", [Pdu]),
    State.



generate_padding(_Size, #state{padding = false}) ->
    [];
generate_padding(Size, State) ->
    generate_padding(Size, State, []).
generate_padding(Size, State, Acc) when Size > 257 ->
    generate_padding(Size - 257, State,
		     Acc ++ [#isis_tlv_padding{size = 255}]);
generate_padding(Size, _State, Acc) ->
    Acc ++ [#isis_tlv_padding{size = (Size - 2)}].

extract_args([{from, From} | T], State) ->
    extract_args(T, State#state{from = From});
extract_args([{system_id, SID} | T], State) ->
    extract_args(T, State#state{system_id = SID});    
extract_args([{interface_name, IfName, _Pid} | T], State) ->
    extract_args(T, State#state{interface_name = IfName});
extract_args([{interface_module, ModName} | T], State) ->
    extract_args(T, State#state{interface_mod = ModName});
extract_args([{interface_pid, Pid} | T], State) ->
    extract_args(T, State#state{interface_pid = Pid});
extract_args([{mode, point_to_multipoint} | T], State) ->
    extract_args(T, State#state{mode = point_to_multipoint});
extract_args([], State) ->
    State.

set_values([{authentication, {none, _Key}} | Vs],
	   #state{pdu_state = PDU} = State) ->
    NewPDU = PDU#isis_pdu_state{authentication = none},
    set_values(Vs, State#state{pdu_state = NewPDU});
set_values([{authentication, {text, Key}} | Vs], 
	   #state{pdu_state = PDU} = State) ->
    NewPDU = PDU#isis_pdu_state{authentication = {text, Key}},
    set_values(Vs, State#state{pdu_state = NewPDU});
set_values([{authentication, {md5, Key}} | Vs],
	   #state{pdu_state = PDU} = State) ->
    NewPDU = PDU#isis_pdu_state{authentication = {md5, Key}},
    set_values(Vs, State#state{pdu_state = NewPDU});
set_values([{level_authentication, Crypto} | Vs],
	   #state{pdu_state = PDU} = State) ->
    NewPDU = PDU#isis_pdu_state{level_authentication = Crypto},
    set_values(Vs, State#state{pdu_state = NewPDU});
set_values([{metric, M} | Vs], State) ->
    case State#state.neighbor of
	undef -> no_op;
	N ->
	    case M =:= State#state.metric of
		true -> no_op;
		false ->
		    do_update_reachability_tlv(add, <<N:6/binary, 0:8>>,
					       0, M, State)
	    end
    end,
    set_values(Vs, State#state{metric = M});
set_values([{csnp_timer, T} | Vs], State) ->
    set_values(Vs, State#state{csnp_timer = T});
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

get_mtu(#state{interface_mod = Mod, interface_pid = Pid}) ->
    Mod:get_mtu(Pid).

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

-spec start_timer(atom(), tuple()) -> reference().
start_timer(hold, State) ->
    erlang:start_timer(State#state.hold_time, self(), hold);
start_timer(iih, State) ->
    erlang:start_timer(isis_protocol:jitter(State#state.hello_interval,
					    ?ISIS_HELLO_JITTER), self(), iih);
start_timer(csnp, State) ->
    erlang:start_timer(isis_protocol:jitter(State#state.csnp_interval,
					    ?ISIS_CSNP_JITTER), self(), csnp);
start_timer(ssn, _State) ->
    erlang:start_timer(isis_protocol:jitter(?ISIS_PSNP_TIMER, ?ISIS_PSNP_JITTER),
		      self(), ssn).

-spec cancel_timers(list()) -> ok.
cancel_timers([H | T]) when H /= undef ->    
    erlang:cancel_timer(H),
    cancel_timers(T);
cancel_timers([H | T]) when H == undef -> 
    cancel_timers(T);
cancel_timers([]) -> 
    ok.

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

%% When stopping, remove the circuit from the system list and remove our neighbor from our reachability list
stopping(#state{from = From, neighbor = N} = State)
  when N =/= undef->
    isis_system:del_circuit(From),
    do_update_reachability_tlv(del, <<N:6/binary, 0:8>>, 0, State#state.metric, State);
stopping(_State) ->
    ok.

%%%===================================================================
%%% verify_interface_addresses
%%%
%%%===================================================================
verify_interface_addresses(IIH, #state{ip_addresses = IPAddresses,
				       ipv6_addresses = IPv6Addresses} = State) ->
    IfIndex = get_ifindex(State),
    Metric = State#state.metric,
    V4 = isis_protocol:filter_tlvs(isis_tlv_ip_interface_address, IIH#isis_p2p_iih.tlv),
    V4Addresses =
	lists:flatten(
	  lists:map(fun(#isis_tlv_ip_interface_address{addresses = A}) -> A end, V4)),
    V41 = sets:from_list(IPAddresses),
    V42 = sets:from_list(V4Addresses),
    V4Remove = lists:map(fun(F) -> {ipv4, {F, IfIndex, self()}} end, sets:to_list(sets:subtract(V41, V42))),
    V4Add = lists:map(fun(F) -> {ipv4, {F, IfIndex, self()}} end, sets:to_list(sets:subtract(V42, V41))),
    isis_system:add_sid_addresses(State#state.level, IIH#isis_p2p_iih.source_id, Metric, V4Add),
    isis_system:delete_sid_addresses(State#state.level, IIH#isis_p2p_iih.source_id, V4Remove),

    V6 = isis_protocol:filter_tlvs(isis_tlv_ipv6_interface_address, IIH#isis_p2p_iih.tlv),
    V6Addresses =
	lists:flatten(
	  lists:map(fun(#isis_tlv_ipv6_interface_address{addresses = A}) -> A end, V6)),
    V61 = sets:from_list(IPv6Addresses),
    V62 = sets:from_list(V6Addresses),
    V6Remove = lists:map(fun(F) -> {ipv6, {F, IfIndex, self()}} end, sets:to_list(sets:subtract(V61, V62))),
    V6Add = lists:map(fun(F) -> {ipv6, {F, IfIndex, self()}} end, sets:to_list(sets:subtract(V62, V61))),
    isis_system:add_sid_addresses(State#state.level, IIH#isis_p2p_iih.source_id, Metric, V6Add),
    isis_system:delete_sid_addresses(State#state.level, IIH#isis_p2p_iih.source_id, V6Remove),
    State#state{ip_addresses = V4Addresses,
		ipv6_addresses = V6Addresses}.

get_ifindex(#state{interface_name = Name}) ->
    I = isis_system:get_interface(Name),
    I#isis_interface.ifindex.
