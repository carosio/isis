%%%-------------------------------------------------------------------
%%% @author Rick Payne <rickp@rossfell.co.uk>
%%% @copyright (C) 2014, Rick Payne
%%% @doc
%%%
%%% @end
%%% Created : 18 Jan 2014 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------
-module(isis_system).

-behaviour(gen_server).

-include("isis_system.hrl").
-include("isis_protocol.hrl").
-include("zclient.hrl").

%% API
-export([start_link/1,
	 %% Interface configuration (add/del/set/list)
	 add_interface/1, del_interface/1, list_interfaces/0, set_interface/2,
	 get_interface/1,
	 %% Enable / disable level on an interface
	 enable_level/2, disable_level/2,
	 %% TLV setting code:
	 set_hostname/1,
	 %% Query
	 areas/0, lsps/0, system_id/0,
	 %% Misc APIs - check autoconf collision etc
	 check_autoconf_collision/1, schedule_lsp_refresh/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE).

-record(state, {autoconf = false :: boolean(),
		system_id,
		system_id_set = false :: boolean(),
		fingerprint = <<>> :: binary(),     %% For autoconfig collisions
		areas = [],
		frags = [] :: [#lsp_frag{}],
		interfaces :: dict(),   %% Our 'state' per interface
		refresh_timer = undef,
		periodic_refresh}).

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
    gen_server:start_link({local, ?MODULE}, ?MODULE, Args, []).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%%
%% Add an interface to this IS-IS system, which will spawn a process
%% to send hello's, handle incoming and outgoing packets etc..
%%
%% @end
%%--------------------------------------------------------------------
-spec add_interface(string()) -> ok | error.
add_interface(Name) ->
    gen_server:call(?MODULE, {add_interface, Name}).

-spec del_interface(string()) -> ok | error.
del_interface(Name) ->
    gen_server:call(?MODULE, {del_interface, Name}).

set_interface(Name, Values) ->
    gen_server:call(?MODULE, {set_interface, Name, Values}).

list_interfaces() ->
    gen_server:call(?MODULE, {list_interfaces}).

get_interface(Name) ->
    gen_server:call(?MODULE, {get_interface, Name}).

enable_level(Interface, Level) ->
    gen_server:call(?MODULE, {enable_level, Interface, Level}).

disable_level(Interface, Level) ->
    gen_server:call(?MODULE, {disable_level, Interface, Level}).

system_id() ->
    gen_server:call(?MODULE, {system_id}).

%% We've received an LSP with our system-id - so check fingerprint
check_autoconf_collision(TLVs) ->
    gen_server:call(?MODULE, {autoconf_collision, TLVs}).

schedule_lsp_refresh() ->
    gen_server:cast(?MODULE, {schedule_lsp_refresh}).

%% Return the areas we're in
areas() ->
    gen_server:call(?MODULE, {areas}).

%% Return the list of LSPs that we originate
lsps() ->
    gen_server:call(?MODULE, {lsps}).

set_hostname(Name) ->
    gen_server:call(?MODULE, {hostname, Name}).


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
    State = #state{interfaces = dict:new()},
    StartState = create_initial_frags(extract_args(Args, State)),
    StartState2 = refresh_lsps(StartState),
    zclient:subscribe(self()),
    %% Periodically check if any of our LSPs need refreshing due to ageout
    Timer = erlang:start_timer(isis_protocol:jitter(?DEFAULT_AGEOUT_CHECK, 10) * 1000,
			       self(), lsp_ageout),
    {ok, StartState2#state{periodic_refresh = Timer}}.

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
handle_call({add_interface, _}, _From,
	    #state{system_id = ID} = State) when is_binary(ID) == false ->
    {reply, {error, "invalid system id"}, State};
handle_call({add_interface, Name}, _From,
	    #state{interfaces = Interfaces} = State) ->
    Interface = 
	case dict:is_key(Name, Interfaces) of
	    true -> dict:fetch(Name, Interfaces);
	    _ -> #isis_interface{name = Name}
	end,
    NextState = do_enable_interface(Interface, State),
    {reply, ok, NextState};

handle_call({del_interface, Name}, _From,
	    #state{interfaces = Interfaces} = State) ->
    NewInterfaces =
	case dict:find(Name, Interfaces) of
	    {ok, Interface} ->
		isis_interface:stop(Interface#isis_interface.pid),
		dict:store(Name, Interface#isis_interface{pid = undef, enabled = false},
			   Interfaces);
	    _ ->
		Interfaces
	end,
    {reply, ok, State#state{interfaces = NewInterfaces}};

handle_call({enable_level, InterfaceName, Level}, _From,
	    #state{interfaces = Interfaces} = State) ->
    Result = 
	case dict:find(InterfaceName, Interfaces) of
	    {ok, Interface} ->
		do_enable_level(Interface, Level);
	    _ ->
		not_found
	end,
    {reply, Result, State};

handle_call({disable_level, InterfaceName, Level}, _From,
	    #state{interfaces = Interfaces} = State) ->
    case dict:find(InterfaceName, Interfaces) of
	{ok, Interface} ->
	    case is_pid(Interface#isis_interface.pid) of
		true -> R = isis_interface:disable_level(Interface#isis_interface.pid, Level),
			{reply, R, State};
		_ ->
		    {reply, not_enabled, State}
	    end;
	_ -> {reply, not_enabled, State}
    end;

handle_call({set_interface, Name, Values}, _From,
	    #state{interfaces = Interfaces} = State) ->
    case dict:find(Name, Interfaces) of
	{ok, Interface} ->
	    case is_pid(Interface#isis_interface.pid) of
		true -> isis_interface:set(Interface#isis_interface.pid, Values);
		_ -> ok
	    end
    end,
    {reply, ok, State};

handle_call({list_interfaces}, _From,
	    #state{interfaces = Interfaces} = State) ->
    Reply = Interfaces,
    {reply, Reply, State};

handle_call({get_interface, Name}, _From,
	    #state{interfaces = Interfaces} = State) ->
    Reply = 
	case dict:find(Name, Interfaces) of
	    {ok, I} -> I;
	    Error -> Error
	end,
    {reply, Reply, State};

handle_call({system_id}, _From,
	    #state{system_id = ID} = State) ->
    {reply, ID, State};

handle_call({autoconf_collision, TLVs}, _From,
	    #state{fingerprint = FP} = State) ->
    %% Scan TLVs to find a hardware fingerprint does not match ours,
    %% and that ours is less than theirs:
    %% 
    %%    When NET duplication occurs, the router with the numerically
    %%    smaller router hardware fingerprint MUST generate a new NET.
    L =  lists:filter(fun(#isis_tlv_hardware_fingerprint{fingerprint = P}) ->
			      FP < P;
			 (_) -> false
		      end, TLVs),
    case length(L) > 0 of
	true -> NextState = autoconf_next_interface(State),
		{reply, true, NextState};
	false -> {reply, false, State}
    end;

handle_call({areas}, _From, #state{areas = Areas} = State) ->
    {reply, Areas, State};

handle_call({lsps}, _From, #state{frags = Frags} = State) ->
    {reply, Frags, State};

handle_call({hostname, Name}, _From, State) ->
    {reply, ok, set_tlv_hostname(Name, State)};

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
handle_cast({schedule_lsp_refresh},
	    #state{refresh_timer = undef} = State) ->
    %% Schedule LSP generation at somepoint in the future. In time, we
    %% could stagger this a bit - have a fast first re-gen, followed
    %% by longer subsequent ones to allow the network to settle.
    Timer = erlang:start_timer(2 * 1000, self(), lsp_refresh),
    {noreply, State#state{refresh_timer = Timer}};
handle_cast({schedule_lsp_refresh}, State) ->
    {noreply, State};
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
handle_info({add_interface, Interface}, State) ->
    {noreply, add_interface(Interface, State)};
handle_info({add_address, Interface, A}, State) ->
    {noreply, add_address(A, Interface, State)};
handle_info({delete_address, Interface, A}, State) ->
    {noreply, delete_address(A, Interface, State)};
handle_info({redistribute_add, Route}, State) ->
    {noreply, add_redistribute(Route, State)};
handle_info({redistribute_delete, Route}, State) ->
    {noreply, delete_redistribute(Route, State)};
handle_info({timeout, _Ref, lsp_ageout}, State) ->
    lsp_ageout_check(State),
    Timer = erlang:start_timer(isis_protocol:jitter(?DEFAULT_AGEOUT_CHECK, 10) * 1000,
			       self(), lsp_ageout),
    {noreply, State#state{periodic_refresh = Timer}};
handle_info({timeout, _Ref, lsp_refresh}, State) ->
    NextState = refresh_lsps(State),
    {noreply, NextState#state{refresh_timer = undef}};
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
extract_args([{autoconf, Fingerprint} | T], State) ->
    %% If we're autoconfig, we need a hardware-fingerprint
    extract_args(T, State#state{autoconf = true, fingerprint = Fingerprint,
				areas = [<<0:(13*8)>>]});
extract_args([{system_id, Id} | T], State) ->
    extract_args(T, State#state{system_id = Id});
extract_args([{areas, Areas} | T], State) ->
    extract_args(T, State#state{areas = Areas});
extract_args([_ | T], State) ->
    extract_args(T, State);
extract_args([], State) ->
    State.

%%%===================================================================
%%% Enable ISIS on an interface
%%% ===================================================================
do_enable_interface(#isis_interface{pid = Pid}, State)  when is_pid(Pid) ->
    State;
do_enable_interface(#isis_interface{name = Name} = Interface, State) ->
    {ok, InterfacePid} = isis_interface:start_link([{name, Name}]),
    erlang:monitor(process, InterfacePid),
    NewInterfaces = dict:store(Name,
			       Interface#isis_interface{pid = InterfacePid,
							enabled = true},
			       State#state.interfaces),
    State#state{interfaces = NewInterfaces}.

%%%===================================================================
%%% Enable a level on an interface
%%% ===================================================================
do_enable_level(#isis_interface{pid = Pid}, Level) when is_pid(Pid) ->
    isis_interface:enable_level(Pid, Level),
    ok;
do_enable_level(_I, _Level) ->
    not_enabled.

%%%===================================================================
%%% Refresh LSPs - take the set of fragments and convert them to
%%% LSPs that we store/update the database with.
%%% ===================================================================
refresh_lsps([#lsp_frag{updated = true} = Frag | T], State) ->
    create_lsp_from_frag(Frag, State),
    refresh_lsps(T, State);
refresh_lsps([H | T], State) ->
    refresh_lsps(T, State);
refresh_lsps([], State) ->
    NewFrags = lists:map(fun(F) -> F#lsp_frag{updated = false} end,
			 State#state.frags),
    State#state{frags = NewFrags}.

refresh_lsps(#state{frags = Frags} = State) ->
    refresh_lsps(Frags, State).

%%%===================================================================
%%% force_refresh_lsps - Ignore the 'updated flag' and force the
%%% update (for instance, if the system id changes).
%%% ===================================================================
force_refresh_lsp(State) ->
    lists:map(fun(F) -> create_lsp_from_frag(F, State) end,
	      State#state.frags).

%%%===================================================================
%%% lsp_ageout_check - for each fragment, lookup the resulting LSP in
%%% the database and check the ageout - refresh if required.
%%% ===================================================================
lsp_ageout_check(#state{frags = Frags} = State) ->
    LSP_Gen = fun(#lsp_frag{level = level_1} = Frag, {L1, L2}) ->
		      {Frag, {L1 ++ [generate_lspid_from_frag(Frag, State)], L2}};
		 (#lsp_frag{level = level_2} = Frag, {L1, L2}) ->
		      {Frag, {L1, L2 ++ [generate_lspid_from_frag(Frag, State)]}}
	      end,
    {_, {L1IDs, L2IDs}} = lists:mapfoldl(LSP_Gen, {[], []}, Frags),
    L1LSPs = isis_lspdb:lookup_lsps(L1IDs, isis_lspdb:get_db(level_1)),
    L2LSPs = isis_lspdb:lookup_lsps(L2IDs, isis_lspdb:get_db(level_2)),
    Updater = fun(#isis_lsp{remaining_lifetime = RL,
			    sequence_number = SeqNo} = L, Level)
		    when RL < (2 * ?DEFAULT_AGEOUT_CHECK) ->
		      %% Update
		      NewLSP = 
			  L#isis_lsp{remaining_lifetime = 1200,
				     sequence_number = SeqNo + 1,
				     last_update = isis_protocol:current_timestamp()},
		      CSum = isis_protocol:checksum(NewLSP),
		      {isis_lspdb:store_lsp(Level, NewLSP#isis_lsp{checksum = CSum}),
		       Level};
		 (_, Level) -> {false, Level}
	      end,
    lists:mapfoldl(Updater, level_1, L1LSPs),
    lists:mapfoldl(Updater, level_2, L2LSPs).

%%%===================================================================
%%% create_lsp_from_frag - take an LSP Fragment, generate the LSP and
%%% store it into the database.
%%% ===================================================================
create_lsp_from_frag(_, #state{system_id = SID}) when SID =:= undefined ->
    no_system_id;
create_lsp_from_frag(#lsp_frag{level = Level} = Frag,
		     #state{system_id = SID} = State)->
    PDUType = case Level of
		  level_1 -> level1_lsp;
		  level_2 -> level2_lsp
	      end,
    LSP_Id = generate_lspid_from_frag(Frag, State),
    SeqNo = case isis_lspdb:lookup_lsps([LSP_Id],
					isis_lspdb:get_db(Level)) of
		[OldLSP] -> OldLSP#isis_lsp.sequence_number + 1;
		_ -> 1
	    end,
    LSP = #isis_lsp{lsp_id = LSP_Id, remaining_lifetime = 1200,
		    last_update = isis_protocol:current_timestamp(),
		    sequence_number = SeqNo, partition = false,
		    overload = false, isis_type = level_1_2,
		    pdu_type = PDUType,
		    tlv = Frag#lsp_frag.tlvs},
    CSum = isis_protocol:checksum(LSP),
    isis_lspdb:store_lsp(Level, LSP#isis_lsp{checksum = CSum}).

generate_lspid_from_frag(#lsp_frag{pseudonode = PN, fragment = FragNo},
			 #state{system_id = SID}) ->
    <<SID/binary, PN:8, FragNo:8>>.

%%%===================================================================
%%% Setup our initial 'fragments' - on startup we just have the node
%%% (0) and our
%%% ===================================================================
create_initial_frags(State) ->
    TLVs = [#isis_tlv_area_address{areas = State#state.areas},
	    #isis_tlv_protocols_supported{protocols = [ipv4, ipv6]},
	    #isis_tlv_extended_reachability{reachability = []}],
    FingerPrintTLVs = 
	case State#state.autoconf of
	    true -> TLVs ++
			[#isis_tlv_hardware_fingerprint{fingerprint = State#state.fingerprint}];
	    _ -> TLVs
	end,
    Creator = fun(TLV, {Level, Frags}) -> 
		      {Level, isis_protocol:merge_whole_tlv(TLV, 0, Level, Frags)}
	      end,
    {_, F} = lists:foldl(Creator, {level_1, []}, FingerPrintTLVs),
    io:format("Created: F: ~p~n", [F]),
    {_, F1} = lists:foldl(Creator, {level_2, F}, FingerPrintTLVs),
    io:format("Created: F1: ~p~n", [F1]),
    NewState = State#state{frags = F1},
    NewState.

set_tlv_hostname(Name, State) ->
    TLV = #isis_tlv_dynamic_hostname{hostname = Name},
    L1Frags = isis_protocol:merge_whole_tlv(TLV, 0, level_1, State#state.frags),
    L2Frags = isis_protocol:merge_whole_tlv(TLV, 0, level_2, L1Frags),
    State#state{frags = L2Frags}.

%%%===================================================================
%%% ZAPI callbacks - handle messages from Zebra/Quagga
%%%===================================================================

%%%===================================================================
%%% Add interface
%%%===================================================================
add_interface(#zclient_interface{
		 name = Name, ifindex = Ifindex,
		 mtu = MTU, mtu6 = MTU6, mac = Mac}, State) ->
    {I, Autoconf} = 
	case dict:is_key(Name, State#state.interfaces) of
	    true -> {dict:fetch(Name, State#state.interfaces),
		     fun(_, S) -> S end};
	    _ -> {#isis_interface{name = Name},
		  fun autoconf_interface/2}
	end,
    Interface = I#isis_interface{ifindex = Ifindex,
				 mac = Mac,
				 mtu = MTU,
				 mtu6 = MTU6},
    NewInterfaces = dict:store(Name, Interface, State#state.interfaces),
    Autoconf(Interface, State#state{interfaces = NewInterfaces}).


%%%===================================================================
%%% If we're doing 'autoconf' we should enable on all interfaces (for
%%% now) and also set the system-id from a MAC address.
%%% ===================================================================
autoconf_interface(#isis_interface{mac = Mac, name = Name} = I,
		   #state{autoconf = true} = State) 
  when byte_size(Mac) =:= 6 ->
    State1 = 
	case State#state.system_id_set of
	    true -> State;
	    _ -> <<ID:(6*8)>> = Mac,
		 DynamicName = lists:flatten(io_lib:format("autoconf-~.16B", [ID])),
		 NextState =
		     set_tlv_hostname(DynamicName, State#state{system_id = Mac,
							system_id_set = true}),
		 force_refresh_lsp(NextState),
		 NextState
	end,
    %% Enable interface and level1...
    State2 = do_enable_interface(I, State1),
    do_enable_level(dict:fetch(Name, State2#state.interfaces), level_1),
    State2;
autoconf_interface(_I, State) ->
    State.

%%%===================================================================
%%% We had a collision, move to the next interface, or shutdown
%%%===================================================================
autoconf_next_interface(State) ->			 
    %% F = fun(#isis_interface{mac = Mac}) when 
    State.

%%%===================================================================
%%% Add address
%%%===================================================================
add_address(#zclient_prefix{afi = AFI, address = Address,
			    mask_length = Mask},
	    Name, State) ->
    I = case dict:is_key(Name, State#state.interfaces) of
	    true ->
		dict:fetch(Name, State#state.interfaces);
	    _ ->
		#isis_interface{name = Name}
	end,
    A = #isis_address{afi = AFI, address = Address, mask = Mask},
    NewA = add_to_list(A, I#isis_interface.addresses),
    NewD = dict:store(Name, I#isis_interface{addresses = NewA}, State#state.interfaces),
    State#state{interfaces = NewD}.

delete_address(#zclient_prefix{} = A, Name, State) ->
    ok.

add_redistribute(#zclient_route{prefix = #zclient_prefix{afi = ipv4, address = Address,
						     mask_length = Mask},
				metric = Metric}, State) ->
    TLV = 
	#isis_tlv_extended_ip_reachability_detail{
	   prefix = Address,
	   mask_len = Mask,
	   metric = Metric,
	   up = true,
	   sub_tlv = []},
    io:format("Handling redist add: ~p~n", [TLV]),
    State;
add_redistribute(#zclient_route{prefix = #zclient_prefix{afi = ipv6, address = Address,
						     mask_length = Mask},
				nexthop = Nexthop, metric = Metric}, State) ->
    TLV = 
	#isis_tlv_ipv6_reachability{prefix = <<Address:128/big>>, up = true,
				    mask_len = Mask, metric = Metric,
				    external = true,
				    sub_tlv = <<>>},
    F1 = isis_protocol:update_tlv(TLV, 0, level_1, State#state.frags),
    F2 = isis_protocol:update_tlv(TLV, 0, level_2, F1),
    State#state{frags = F2}.


delete_redistribute(#zclient_route{prefix = #zclient_prefix{afi = ipv4, address = Address,
							    mask_length = Mask},
				   metric = Metric}, State) ->
    %% TLV = 
    %% 	#isis_tlv_extended_ip_reachability_detail{
    %% 	   prefix = Address,
    %% 	   mask_len = Mask,
    %% 	   metric = Metric,
    %% 	   up = true,
    %% 	   sub_tlv = []},
    State;
delete_redistribute(#zclient_route{prefix = #zclient_prefix{afi = ipv6, address = Address,
							    mask_length = Mask},
				   metric = Metric}, State) ->
    TLV = 
	#isis_tlv_ipv6_reachability{prefix = <<Address:128>>, up = true,
				    mask_len = Mask, metric = Metric,
				    sub_tlv = []},
    F1 = isis_protocol:delete_tlv(TLV, 0, level1, State#state.frags),
    F2 = isis_protocol:delete_tlv(TLV, 0, level2, F1),
    State#state{frags = F2}.

add_to_list(Item, List) ->
    Replacer = fun(I, _) when I =:= Item ->
		       {I, true};
		  (I, Acc) -> {I, Acc}
	       end,
    {NewList, Found} = lists:mapfoldl(Replacer, false, List),
    case Found of
	true -> NewList;
	_ -> NewList ++ [Item]
    end.
    
