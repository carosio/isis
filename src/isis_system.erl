%%%-------------------------------------------------------------------
%%% @author Rick Payne <rickp@rossfell.co.uk>
%%% @copyright (C) 2014, Alistair Woodman, California USA <awoodman@netdef.org>
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
	 set_state/1, get_state/1,
	 %% Interface configuration (add/del/set/list)
	 add_interface/1, del_interface/1, list_interfaces/0,
	 set_interface/2, set_interface/3, get_interface/1,
	 %% Enable / disable level on an interface
	 enable_level/2, disable_level/2,
	 %% Clear
	 clear_neighbors/0,
	 %% TLV setting code:
	 set_hostname/1,
	 %% Add/Remove areas
	 add_area/1, del_area/1,
	 %% System ID
	 set_system_id/1,
	 %% Query
	 areas/0, lsps/0, system_id/0, autoconf_status/0,
	 %% Misc APIs - check autoconf collision etc
	 check_autoconf_collision/1, schedule_lsp_refresh/0, process_spf/1,
	 bump_lsp/4,
	 %% TLV Update routines
	 update_tlv/4, delete_tlv/4,
	 %% System Name handling
	 add_name/2, delete_name/1, lookup_name/1,
	 %% Handle System ID mapping
	 add_sid_addresses/2, delete_sid_addresses/2,
	 %% pseudonodes
	 allocate_pseudonode/2, deallocate_pseudonode/2,
	 %% Misc
	 address_to_string/1, address_to_string/2, dump_config/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE).

-record(state, {autoconf = false :: boolean(),
		system_id,
		system_id_set = false :: boolean(),
		fingerprint = <<>> :: binary(),     %% For autoconfig collisions
		hostname = [],
		areas = [],
		frags = [] :: [#lsp_frag{}],
		max_lsp_lifetime = ?ISIS_MAX_LSP_LIFETIME,
		pseudonodes :: dict(),  %% PID -> Pseudonode mapping
		reachability :: dict(),
		interfaces,             %% Our 'state' per interface
		redistributed_routes,
		ignore_list = [],       %% Interfaces to ignore
		system_ids :: dict(),   %% SID -> Neighbor address
		refresh_timer = undef,
		periodic_refresh,
		names}).

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
    Pid = 
	case ets:lookup(isis_interfaces, Name) of
	    [I] -> I#isis_interface.pid;
	    _ -> unknown
	end,
    case is_pid(Pid) of
	true -> isis_interface:set(Pid, Values);
	_ -> not_enabled
    end.

set_interface(Name, Level, Values) ->
    Pid = 
	case ets:lookup(isis_interfaces, Name) of
	    [I] -> I#isis_interface.pid;
	    _ -> unknown
	end,
    case is_pid(Pid) of
	true -> LevelPid = isis_interface:get_level_pid(Pid, Level),
		case is_pid(LevelPid) of
		    true -> isis_interface_level:set(LevelPid, Values);
		    _ -> not_enabled
		end;
	_ -> not_enabled
    end.

list_interfaces() ->
    ets:tab2list(isis_interfaces).

get_interface(Name) ->
    case ets:lookup(isis_interfaces, Name) of
	[I] -> I;
	_ -> unknown
    end.

enable_level(Interface, level_1) ->
    case ets:lookup(isis_interfaces, Interface) of
	[I] -> do_enable_level(I, level_1);
	_ -> not_found
    end;
enable_level(Interface, level_2) ->
    case ets:lookup(isis_interfaces, Interface) of
	[I] -> do_enable_level(I, level_2);
	_ -> not_found
    end;
enable_level(_, _) ->
    io:format("Invalid level, should be either level_1 or level_2~n", []),
    bad_level.

disable_level(Interface, level_1) ->
    case ets:lookup(isis_interfaces, Interface) of
	[I] -> 
	    case is_pid(I#isis_interface.pid) of
		true -> isis_interface:disable_level(I#isis_interface.pid, level_1);
		_ -> not_enabled
	    end;
	_ -> not_found
    end;
disable_level(Interface, level_2) ->
    case ets:lookup(isis_interfaces, Interface) of
	[I] -> 
	    case is_pid(I#isis_interface.pid) of
		true -> isis_interface:disable_level(I#isis_interface.pid, level_2);
		_ -> not_enabled
	    end;
	_ -> not_found
    end;
disable_level(_, _) ->
    io:format("Invalid level, should be either level_1 or level_2~n", []),
    bad_level.

clear_neighbors() ->
    gen_server:call(?MODULE, {clear_neighbors}).

system_id() ->
    gen_server:call(?MODULE, {system_id}).

set_system_id(Id) when is_binary(Id), byte_size(Id) =:= 6->
    gen_server:call(?MODULE, {set_system_id, Id});
set_system_id(_) ->
    io:format("System ID should be a 6 byte binary~n", []),
    bad_systemid.


autoconf_status() ->
    gen_server:call(?MODULE, {autoconf_status}).

%% We've received an LSP with our system-id - so check fingerprint
check_autoconf_collision(TLVs) ->
    gen_server:call(?MODULE, {autoconf_collision, TLVs}).

schedule_lsp_refresh() ->
    gen_server:cast(?MODULE, {schedule_lsp_refresh}).

update_tlv(TLV, Node, Level, Interface) ->
    %% io:format("Updating TLVs for node ~p ~p~n~p~n~p~n",
    %%  	      [Node, Level, TLV,
    %% 	       element(2, process_info(self(), backtrace))]),
    gen_server:cast(?MODULE, {update_tlv, TLV, Node, Level, Interface}).

delete_tlv(TLV, Node, Level, Interface) ->
    gen_server:cast(?MODULE, {delete_tlv, TLV, Node, Level, Interface}).

%% Return the areas we're in
areas() ->
    gen_server:call(?MODULE, {areas}).

add_area(Area) ->
    gen_server:call(?MODULE, {add_area, Area}).

del_area(Area) ->
    gen_server:call(?MODULE, {del_area, Area}).

%% Return the list of LSPs that we originate
lsps() ->
    gen_server:call(?MODULE, {lsps}).

set_hostname(Name) ->
    gen_server:call(?MODULE, {hostname, Name}).

process_spf(SPF) ->
    gen_server:cast(?MODULE, {process_spf, SPF}).

add_sid_addresses(_, []) ->
    ok;
add_sid_addresses(SID, Addresses) ->
    gen_server:cast(?MODULE, {add_sid, SID, Addresses}).

delete_sid_addresses(_, []) ->
    ok;
delete_sid_addresses(SID, Addresses) ->
    gen_server:cast(?MODULE, {delete_sid, SID, Addresses}).

add_name(SID, Name) ->
    gen_server:cast(?MODULE, {add_name, SID, Name}).
delete_name(SID) ->
    gen_server:cast(?MODULE, {delete_name, SID}).
lookup_name(<<SID:6/binary, PN:8>>) ->
    Names = ets:lookup(isis_names, SID),
    case length(Names) >= 1 of
	true ->
	    Name = lists:nth(1, Names),
	    lists:flatten(io_lib:format("~s-~2.16.0B",
			  [Name#isis_name.name, PN]));
	_ ->
	    lists:flatten(io_lib:format("~4.16.0B.~4.16.0B.~4.16.0B-~2.16.0B",
					[X || <<X:16>> <= SID] ++ [PN]))
    end;
lookup_name(<<SID:6/binary>>) ->
    Names = ets:lookup(isis_names, SID),
    case length(Names) >= 1 of
	true ->
	    Name = lists:nth(1, Names),
	    Name#isis_name.name;
	_ ->
	    lists:flatten(io_lib:format("~4.16.0B.~4.16.0B.~4.16.0B",
					[X || <<X:16>> <= SID]))
    end.

allocate_pseudonode(Pid, Level) ->
    gen_server:call(?MODULE, {allocate_pseudonode, Pid, Level}).

deallocate_pseudonode(Node, Level) ->
    gen_server:call(?MODULE, {deallocate_pseudonode, Node, Level}).

bump_lsp(Level, Node, Frag, SeqNo) ->
    gen_server:cast(?MODULE, {bump, Level, Node, Frag, SeqNo}).

set_state(Item) ->
    gen_server:cast(?MODULE, {set_state, Item}).

get_state(Item) ->
    gen_server:call(?MODULE, {get_state, Item}).

dump_config() ->
    gen_server:call(?MODULE, {dump_config}).

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
    Interfaces = ets:new(isis_interfaces, [named_table, ordered_set,
					   {keypos, #isis_interface.name}]),
    Redist = ets:new(redistributed_routes, [named_table, bag,
					    {keypos, #zclient_route.prefix}]),
    State = #state{system_ids = dict:new(),
		   interfaces = Interfaces,
		   redistributed_routes = Redist,
		   pseudonodes = dict:new(),
		   reachability = dict:new()},
    StartState = create_initial_frags(extract_args(Args, State)),
    StartState2 = refresh_lsps(StartState),
    zclient:subscribe(self()),
    %% Periodically check if any of our LSPs need refreshing due to ageout
    Timer = erlang:start_timer(isis_protocol:jitter(?DEFAULT_AGEOUT_CHECK, 10) * 1000,
			       self(), lsp_ageout),
    Names = ets:new(isis_names, [named_table, ordered_set,
				 {keypos, #isis_name.system_id}]),
    isis_lspdb:set_system_id(level_1, StartState2#state.system_id),
    isis_lspdb:set_system_id(level_2, StartState2#state.system_id),
    {ok, StartState2#state{periodic_refresh = Timer, names = Names}}.

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
	case ets:lookup(Interfaces, Name) of
	    [I] -> I;
	    _ -> #isis_interface{name = Name}
	end,
    NextState = do_enable_interface(Interface, State),
    {reply, ok, NextState};

handle_call({del_interface, Name}, _From,
	    #state{interfaces = Interfaces} = State) ->
    case ets:lookup(Interfaces, Name) of
	[Interface] ->
	    isis_interface:stop(Interface#isis_interface.pid),
	    ets:insert(Interfaces, Interface#isis_interface{pid = undefined, enabled = false});
	_ ->
	    ok
    end,
    {reply, ok, State};

handle_call({clear_neighbors}, _From,
	    #state{interfaces = Interfaces} = State) ->
    lists:map(fun(I) ->
		     isis_interface:clear_neighbors(I#isis_interface.pid)
	     end, ets:tab2list(Interfaces)),
    {reply, ok, State};
		     
handle_call({system_id}, _From,
	    #state{system_id = ID} = State) ->
    {reply, ID, State};
handle_call({set_system_id, undefined}, _From, State) ->
    lager:info("System ID has been unset", []),
    isis_lspdb:set_system_id(level_1, undefined),
    isis_lspdb:set_system_id(level_2, undefined),
    NewState = purge_all_lsps(State),
    {reply, ok, NewState#state{system_id = undefined,
			       system_id_set = false}};
handle_call({set_system_id, Id}, _From, State)
  when is_binary(Id), byte_size(Id) =:= 6 ->
    lager:info("System ID set to ~p", [Id]),
    isis_lspdb:set_system_id(level_1, Id),
    isis_lspdb:set_system_id(level_2, Id),
    NewState = 
	case State#state.system_id =:= Id of
	    true -> State;
	    false ->
		case State#state.system_id_set of
		    true -> purge_all_lsps(State);
		    false -> State
		end
	end,
    {reply, ok, NewState#state{system_id = Id,
			       system_id_set = true}};
handle_call({set_system_id, _}, _From, State) ->
    {reply, invalid_sid, State};

handle_call({autoconf_status}, _From,
	    #state{autoconf = A, system_id_set = B} = State) ->
    {reply, {A, B}, State};

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

handle_call({add_area, A}, _From, #state{areas = Areas} = State) ->
    NewAreas = lists:sort(lists:delete(A, Areas) ++ [A]),
    {reply, ok, State#state{areas = NewAreas}};

handle_call({del_area, A}, _From, #state{areas = Areas} = State) ->
    {reply, ok, State#state{areas = lists:delete(A, Areas)}};

handle_call({lsps}, _From, #state{frags = Frags} = State) ->
    {reply, Frags, State};

handle_call({hostname, Name}, _From, State) ->
    {reply, ok, set_tlv_hostname(Name, State)};

handle_call({allocate_pseudonode, Pid, Level}, _From, State) ->
    {PN, NewState} = allocate_pseudonode(Pid, Level, State),
    {reply, PN, NewState};

handle_call({deallocate_pseudonode, Node, Level}, _From, State) ->
    {Reply, NewState} = deallocate_pseudonode(Node, Level, State),
    {reply, Reply, NewState};

handle_call({get_state, Item}, _From, State) ->
    {reply, extract_state(Item, State), State};

handle_call({dump_config}, _From, State) ->
    dump_config(State),
    {reply, ok, State};

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
    %% io:format("LSP Refresh scheduled~n", []),
    Timer = erlang:start_timer(2 * 1000, self(), lsp_refresh),
    {noreply, State#state{refresh_timer = Timer}};
handle_cast({schedule_lsp_refresh}, State) ->
    {noreply, State};
handle_cast({update_tlv, TLV, Node, Level, Interface}, State) ->
    update_tlv(TLV, Node, Level, Interface, State);

handle_cast({delete_tlv, TLV, Node, Level, Interface}, State) ->
    delete_tlv(TLV, Node, Level, Interface, State);

handle_cast({add_sid, SID, Addresses}, #state{system_ids = IDs} = State) ->
    D1 = case dict:find(SID, IDs) of
	     error -> dict:store(SID, Addresses, IDs);
	     {ok, As} ->
		 S1 = sets:from_list(Addresses),
		 S2 = sets:from_list(As),
		 NewAs = sets:to_list(sets:union([S1, S2])),
		 dict:store(SID, NewAs, IDs)
	 end,
    isis_lspdb:schedule_spf(level_1, "Neighbor change"),
    isis_lspdb:schedule_spf(level_2, "Neighbor change"),
    {noreply, State#state{system_ids = D1}};
handle_cast({delete_sid, SID, Addresses}, State) ->
    D1 = case dict:find(SID, State#state.system_ids) of
	     error -> State#state.system_ids;
	     {ok, As} ->
		 S1 = sets:from_list(As),
		 S2 = sets:from_list(Addresses),
		 NewAs = sets:to_list(sets:subtract(S1, S2)),
		 dict:store(SID, NewAs, State#state.system_ids)
	 end,
    {noreply, State#state{system_ids = D1}};
handle_cast({process_spf, {Level, Time, SPF, Reason}}, State) ->
    Table = 
	lists:filtermap(
	  fun({<<Node:7/binary>>, NHID, Metric, As, Nodes})
	     when is_list(As) ->
		  case length(As) of
		      0 -> false;
		      _ ->
			  case dict:find(NHID, State#state.system_ids) of
			      {ok, NH} -> {true, {
					     lookup_name(Node),
					     lookup_name(NHID),
					     NH, Metric, As, Nodes}};
			      _ -> false
			  end
		  end;
	     (_) -> false
	  end, SPF),
    spf_summary:notify_subscribers({Time, Level, Table, Reason}),
    {noreply, State};
handle_cast({add_name, SID, Name}, State) ->
    N = #isis_name{system_id = SID, name = Name},
    ets:insert(State#state.names, N),
    {noreply, State};
handle_cast({delete_name, SID}, State) ->
    N = #isis_name{system_id = SID},
    ets:delete(State#state.names, N),
    {noreply, State};
handle_cast({bump, Level, Node, Frag, SeqNo}, State) ->
    NewState = do_bump_lsp(Level, Node, Frag, SeqNo, State),
    {noreply, NewState};
handle_cast({set_state, Item}, State) ->
    {noreply, set_state(Item, State)};
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
handle_info({del_address, Interface, A}, State) ->
    {noreply, delete_address(A, Interface, State)};
handle_info({redistribute_add, Route}, State) ->
    {noreply, add_redistribute(Route, State)};
handle_info({redistribute_delete, Route}, State) ->
    {noreply, delete_redistribute(Route, State)};
handle_info({router_id, Address}, State) ->
    {noreply, update_router_id(Address, State)};
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
extract_args([{autoconf, true} | T], State) ->
    %% If we're autoconfig, we need a hardware-fingerprint
    extract_args(T, State#state{autoconf = true,
				areas = [<<0:(13*8)>>]});
extract_args([{autoconf_fingerprint, FP} | T], State) ->
    %% If we're autoconfig, we need a hardware-fingerprint
    extract_args(T, State#state{fingerprint = FP});
extract_args([{system_id, Id} | T], State) ->
    extract_args(T, State#state{system_id = Id});
extract_args([{areas, Areas} | T], State) ->
    extract_args(T, State#state{areas = Areas});
extract_args([{ignore_interfaces, Is} | T], State) ->
    extract_args(T, State#state{ignore_list = Is});
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
    ets:insert(State#state.interfaces,
	       Interface#isis_interface{pid = InterfacePid,
					enabled = true}),
    State.

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
refresh_lsps([#lsp_frag{updated = true} = Frag | T],
	     #state{system_id_set = true} = State) ->
    %% LSPId = generate_lspid_from_frag(Frag, State),
    %% io:format("Refreshing LSP ~p~n", [LSPId]),
    create_lsp_from_frag(Frag, State),
    refresh_lsps(T, State);
refresh_lsps([_H | T], State) ->
    refresh_lsps(T, State);
refresh_lsps([], State) ->
    %% No more frags, reset the update flag on whole list...
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
lsp_ageout_check(#state{system_id_set = false}) ->
    no_system_id;
lsp_ageout_check(#state{frags = Frags} = State) ->
    LSP_Gen = fun(#lsp_frag{level = level_1} = Frag, {L1, L2}) ->
		      {Frag, {L1 ++ [generate_lspid_from_frag(Frag, State)], L2}};
		 (#lsp_frag{level = level_2} = Frag, {L1, L2}) ->
		      {Frag, {L1, L2 ++ [generate_lspid_from_frag(Frag, State)]}}
	      end,
    {_, {L1IDs, L2IDs}} = lists:mapfoldl(LSP_Gen, {[], []}, Frags),
    L1LSPs = isis_lspdb:lookup_lsps(L1IDs, isis_lspdb:get_db(level_1)),
    L2LSPs = isis_lspdb:lookup_lsps(L2IDs, isis_lspdb:get_db(level_2)),
    Updater = fun(#isis_lsp{lsp_id = Id,
			    remaining_lifetime = RL,
			    sequence_number = SeqNo} = L, Level)
		    when RL < (2 * ?DEFAULT_AGEOUT_CHECK) ->
		      %% Update
		      NewLSP = 
			  L#isis_lsp{remaining_lifetime = State#state.max_lsp_lifetime,
				     sequence_number = SeqNo + 1,
				     last_update = isis_protocol:current_timestamp()},
		      CSum = isis_protocol:checksum(NewLSP),
		      CompleteLSP = NewLSP#isis_lsp{checksum = CSum},
		      isis_lspdb:flood_lsp(Level, ets:tab2list(State#state.interfaces),
					   CompleteLSP),
		      {isis_lspdb:store_lsp(Level, CompleteLSP), Level};
		 (_, Level) -> 
		      {false, Level}
	      end,
    lists:mapfoldl(Updater, level_1, L1LSPs),
    lists:mapfoldl(Updater, level_2, L2LSPs).

%%%===================================================================
%%% create_lsp_from_frag - take an LSP Fragment, generate the LSP and
%%% store it into the database.
%%% ===================================================================
create_lsp_from_frag(_, #state{system_id = SID}) when SID =:= undefined ->
    no_system_id;
create_lsp_from_frag(#lsp_frag{level = Level, sequence = SN} = Frag,
		     State)->
    PDUType = case Level of
		  level_1 -> level1_lsp;
		  level_2 -> level2_lsp
	      end,
    LSP_Id = generate_lspid_from_frag(Frag, State),
    SeqNo = case isis_lspdb:lookup_lsps([LSP_Id],
					isis_lspdb:get_db(Level)) of
		[OldLSP] -> case OldLSP#isis_lsp.sequence_number < SN of
				true -> SN;
				_ -> OldLSP#isis_lsp.sequence_number + 1
			    end;
		_ -> 1
	    end,
    LSP = #isis_lsp{lsp_id = LSP_Id, remaining_lifetime = State#state.max_lsp_lifetime,
		    last_update = isis_protocol:current_timestamp(),
		    sequence_number = SeqNo, partition = false,
		    overload = false, isis_type = level_1_2,
		    pdu_type = PDUType,
		    tlv = Frag#lsp_frag.tlvs},
    CSum = isis_protocol:checksum(LSP),
    isis_lspdb:store_lsp(Level, LSP#isis_lsp{checksum = CSum}),
    isis_lspdb:flood_lsp(Level, ets:tab2list(State#state.interfaces), LSP).

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
		      {Level, isis_protocol:update_tlv(TLV, 0, Level, Frags)}
	      end,
    {_, F} = lists:foldl(Creator, {level_1, []}, FingerPrintTLVs),
    {_, F1} = lists:foldl(Creator, {level_2, F}, FingerPrintTLVs),
    NewState = State#state{frags = F1},
    NewState.

create_frag(PN, Level) when PN > 0, PN =< 255 ->
    #lsp_frag{level = Level,
	      pseudonode = PN};
create_frag(PN, Level) ->
    io:format("Tried to create PN ~p for ~p~n", [PN, Level]),
    error.

update_tlv(#isis_tlv_extended_reachability{reachability =
					       [#isis_tlv_extended_reachability_detail{
						   neighbor = D}
						]} = TLV,
	   Node, Level, Interface,
	   #state{frags = Frags, reachability = Reachability} = State) ->
    {NewD, NewIs} = 
	case dict:find({Node, Level, D}, Reachability) of
	    {ok, Is} ->
		case lists:member(Interface, Is) of
		    true -> {Reachability, Is};
		    _ -> {dict:store({Node, Level, D}, [Interface | Is], Reachability),
			  [Interface | Is]}
		end;
	    _ -> {dict:store({Node, Level, D}, [Interface], Reachability), [Interface]}
	end,
    lager:debug("Reachability for {~p, ~p, ~p} now via ~p", [Node, Level, D, NewIs]),
    NewFrags = isis_protocol:update_tlv(TLV, Node, Level, Frags),
    schedule_lsp_refresh(),
    isis_lspdb:schedule_spf(level_1, "Self-originated TLV change"),
    isis_lspdb:schedule_spf(level_2, "Self-originated TLV change"),
    {noreply, State#state{frags = NewFrags, reachability = NewD}};
update_tlv(TLV, Node, Level, Interface, #state{frags = Frags} = State) ->
    NewFrags = isis_protocol:update_tlv(TLV, Node, Level, Frags),
    schedule_lsp_refresh(),
    isis_lspdb:schedule_spf(level_1, "Self-originated TLV change"),
    isis_lspdb:schedule_spf(level_2, "Self-originated TLV change"),
    {noreply, State#state{frags = NewFrags}}.

delete_tlv(#isis_tlv_extended_reachability{reachability =
					       [#isis_tlv_extended_reachability_detail{
						   neighbor = D}
						]} = TLV,
	   Node, Level, Interface,
	   #state{frags = Frags, reachability = Reachability} = State) ->
    {NewD, NewIs} = 
	case dict:find({Node, Level, D}, Reachability) of
	    {ok, Is} -> TIs = lists:filter(fun(TI) -> TI =/= Interface end, Is),
			case length(TIs) =:= length(Is) of
			    true -> {Reachability, TIs};
			    _ -> {dict:store({Node, Level, D}, TIs, Reachability), TIs}
			end;
	    _ -> %% Removing something we don't know about?
		lager:error("Removing {~p, ~p, ~p} for ~s but we have no state!",
			    [Node, Level, D, Interface]),
		{Reachability, []}
	end,
    lager:debug("Reachability for {~p, ~p, ~p} now via ~p", [Node, Level, D, NewIs]),
    {NewD2, NewFrags} = 
	case length(NewIs) =:= 0 of
	    true ->
		D2 = dict:erase({Node, Level, D}, NewD),
		TF = isis_protocol:delete_tlv(TLV, Node, Level, Frags),
		schedule_lsp_refresh(),
		{D2, TF};
	_ -> {NewD, Frags}
    end,
    {noreply, State#state{frags = NewFrags, reachability = NewD2}};
delete_tlv(TLV, Node, Level, Interface, #state{frags = Frags} = State) ->
    NewFrags = isis_protocol:delete_tlv(TLV, Node, Level, Frags),
    schedule_lsp_refresh(),
    {noreply, State#state{frags = NewFrags}}.

set_tlv_hostname(Name, State) ->
    TLV = #isis_tlv_dynamic_hostname{hostname = Name},
    L1Frags = isis_protocol:update_tlv(TLV, 0, level_1, State#state.frags),
    L2Frags = isis_protocol:update_tlv(TLV, 0, level_2, L1Frags),
    State#state{frags = L2Frags, hostname = Name}.

allocate_pseudonode(Pid, Level, #state{frags = Frags} = State) ->
    F = fun(#lsp_frag{pseudonode = PN, level = L})
	      when Level =:= L ->
		{true, PN};
	   (_) -> false
	end,
    S0 = sets:from_list(lists:filtermap(F, Frags)),
    %% Any lasting PN in our DB?
    SID = State#state.system_id,
    InUseFrags = 
	lists:filtermap(
	  fun(#isis_lsp{lsp_id = <<LSID:6/binary, LPN:8, _:8>>}) ->
		  case LSID =:= SID of
		      true -> {true, LPN};
		      _ -> false
		  end
	  end, ets:tab2list(isis_lspdb:get_db(Level))),
    S1 = sets:union(S0, sets:from_list(InUseFrags)),
    S2 = sets:from_list(lists:seq(1, 255)),
    %% Look away now - shuffle the available set of Pseudonodes
    L = [X||{_,X} <- lists:sort([ {random:uniform(), N} ||
				    N <- sets:to_list(sets:subtract(S2, S1))])],
    NewPN = lists:nth(1, L),
    NewDict = dict:store(Pid, {Level, NewPN}, State#state.pseudonodes),
    NewFrag = create_frag(NewPN, Level),
    {NewPN, State#state{pseudonodes = NewDict,
			frags = [NewFrag] ++ State#state.frags}}.

deallocate_pseudonode(Node, Level, State) ->
    %% Purge any remaining pseudonode fragments...
    MatchFun =
	fun(PN, L)
	    when L =:= Level, PN =:= Node ->
		true;
	   (_, _) -> false
	end,
    NewFrags = purge_lsps(MatchFun, State),
    %% Now remove this reference from the pseudonode dict
    G = fun(_, {L, PN}) when L =:= Level, PN =:= Node -> false;
	   (_, _) -> false
	end,
    H = fun({Node, Level, _}, _) -> false;
	   ({_, _, _}, _) -> false
	end,
    NewPNDict = dict:filter(G, State#state.pseudonodes),
    NewRDict = dict:filter(H, State#state.reachability),
    {ok, State#state{frags = NewFrags,
		     pseudonodes = NewPNDict,
		     reachability = NewRDict}}.

%%--------------------------------------------------------------------
%% @doc
%%
%% Purge all self-generated LSPs for which the provided MatchFun
%% matches.
%%
%% @end
%%--------------------------------------------------------------------
purge_lsps(MatchFun, State) ->
    F = fun(#lsp_frag{pseudonode = PN, level = L} = Frag) ->
		case MatchFun(PN, L) of
		    true -> LSP_Id = generate_lspid_from_frag(Frag, State),
			    purge_lsp(L, LSP_Id, State),
			    false;
		    _ -> true
		end
	end,
    lists:filter(F, State#state.frags).

%%--------------------------------------------------------------------
%% @doc
%%
%% Purge all self-generated LSPs
%%
%% @end
%%--------------------------------------------------------------------
purge_all_lsps(State) ->
    lager:error("!!!!!!!!!!!!!! ALL LSPS PURGED! !!!!!!!!!!!!!!!!", []),
    NewFrags = purge_lsps(fun(_, _) -> true end, State),
    State#state{frags = NewFrags}.

%%--------------------------------------------------------------------
%% @doc
%%
%% Purge an LSP
%%
%% @end
%%--------------------------------------------------------------------
purge_lsp(Level, LSP, _State) ->
    lager:error("Purging LSP: ~p", [LSP]),
    isis_lspdb:purge_lsp(Level, LSP).

%%--------------------------------------------------------------------
%% @doc
%%
%% Bump the sequence number on a Frag and flood
%%
%% @end
%%--------------------------------------------------------------------
do_bump_lsp(Level, Node, Frag, SeqNo, State) ->
    DoBump = fun(#lsp_frag{level = L, pseudonode = N,
			   fragment = F} = LspFrag)
		   when L =:= Level, N =:= Node, F =:= Frag ->
		     LspFrag#lsp_frag{sequence = (SeqNo + 1),
				      updated = true};
		(F) -> F
	     end,
    NewFrags = lists:map(DoBump, State#state.frags),
    schedule_lsp_refresh(),
    State#state{frags = NewFrags}.

%%%===================================================================
%%% ZAPI callbacks - handle messages from Zebra/Quagga
%%%===================================================================

%%%===================================================================
%%% Add interface
%%%===================================================================
add_interface(#zclient_interface{
		 name = Name, ifindex = Ifindex, flags = Flags,
		 mtu = MTU, mtu6 = MTU6, mac = Mac}, State) ->
    {I, Autoconf} = 
	case ets:lookup(State#state.interfaces, Name) of
	    [Intf] -> {Intf, fun(_, S) -> S end};
	    _ -> {#isis_interface{name = Name},
		  fun autoconf_interface/2}
	end,
    Interface = I#isis_interface{ifindex = Ifindex,
				 flags = Flags,
				 mac = Mac,
				 mtu = MTU,
				 mtu6 = MTU6},
    ets:insert(State#state.interfaces, Interface),
    Autoconf(Interface, State).


%%%===================================================================
%%% If we're doing 'autoconf' we should enable on all interfaces (for
%%% now) and also set the system-id from a MAC address.
%%% ===================================================================
is_valid_interface(Name, #state{ignore_list = Ignores}) when is_list(Name) ->
    % An interface name is expected to consist of a reasonable
    % subset of all characters, use a whitelist and extend it if needed
    case lists:member(Name, Ignores) of
	true -> false;
	_ ->
	    Name == [C || C <- Name, (((C bor 32) >= $a) and ((C bor 32) =< $z))
			      or ((C >= $0) and (C =< $9)) or (C == $.)]
    end.

autoconf_interface(#isis_interface{mac = Mac, name = Name} = I,
		   #state{autoconf = true, ignore_list = Igs} = State) 
  when byte_size(Mac) =:= 6 ->
    case is_valid_interface(Name, State) of
	true ->
	    State1 = 
		case State#state.system_id_set =:= true of
		    true -> State;
		    _ -> <<ID:(6*8)>> = Mac,
			 %%DynamicName = lists:flatten(io_lib:format("autoconf-~.16B", [ID])),
			 {ok, DynamicName} = inet:gethostname(),
			 isis_lspdb:set_system_id(level_1, Mac),
			 isis_lspdb:set_system_id(level_2, Mac),
			 lager:info("System ID set to ~p", [Mac]),
			 NextState =
			     set_tlv_hostname(DynamicName, State#state{system_id = Mac,
								       system_id_set = true}),
			 force_refresh_lsp(NextState),
			 NextState
		end,
	    %% Enable interface and level1...
	    State2 = do_enable_interface(I, State1),
	    [Interface] = ets:lookup(State2#state.interfaces, Name),
	    do_enable_level(Interface, level_1),
	    LevelPid = isis_interface:get_level_pid(Interface#isis_interface.pid, level_1),
	    isis_interface_level:set(LevelPid,
				     [{encryption, text, <<"isis-autoconf">>},
				      {metric, ?DEFAULT_AUTOCONF_METRIC},
				      {priority, ?DEFAULT_PRIORITY}]),
	    State2;
	_ ->
	    State
    end;
autoconf_interface(_I, State) ->
    State.

%%%===================================================================
%%% We had a collision, move to the next interface, or shutdown
%%%===================================================================
autoconf_next_interface(State) ->			 
    %% F = fun(#isis_interface{mac = Mac}) when 
    State.

update_address_tlv(Updater, ipv4, Address, Mask, State) ->
    ABin = <<Address:32/big>>,
    case ABin of
	<<127:8, _:24>> -> State;
	_ ->
	    TLV = #isis_tlv_extended_ip_reachability{
		     reachability =
			 [#isis_tlv_extended_ip_reachability_detail{
			     prefix = Address,
			     mask_len = Mask,
			     metric = 0,
			     up = true,
			     sub_tlv = []}]},
	    update_frags(Updater, TLV, 0, State)
    end;
update_address_tlv(Updater, ipv6, Address, Mask, State) ->
    ABin = <<Address:128/big>>,
    case ABin of
	<<16#FE80:16, _:112>> -> State;
	<<0:127, 1:1>> -> State;
	_ ->	    
	    MaskLenBytes = erlang:trunc((Mask + 7) / 8),
	    A = Address bsr (128 - Mask),
	    TLV = #isis_tlv_ipv6_reachability{
		     reachability =
			 [#isis_tlv_ipv6_reachability_detail{
			     prefix = <<A:(MaskLenBytes * 8)>>, up = true,
			     mask_len = Mask, metric = 0,
			     external = false}]
		    },
	    update_frags(Updater, TLV, 0, State)
    end.

%%%===================================================================
%%% Add address
%%%===================================================================
add_address(#zclient_prefix{afi = AFI, address = Address,
			    mask_length = Mask},
	    Name, State) ->
    I = case ets:lookup(State#state.interfaces, Name) of
	    [Intf] -> Intf;
	    _ ->
		#isis_interface{name = Name}
	end,
    A = #isis_address{afi = AFI, address = Address, mask = Mask},
    NewA = add_to_list(A, I#isis_interface.addresses),
    ets:insert(State#state.interfaces, I#isis_interface{addresses = NewA}),
    NewState = 
	case is_valid_interface(I#isis_interface.name, State) of
	    true -> update_address_tlv(fun isis_protocol:update_tlv/4,
				       AFI, Address, Mask, State);
	    _ -> State
	end,
    NewState.

delete_address(#zclient_prefix{afi = AFI, address = Address, mask_length = Mask} = R,
	       Name, State) ->
    A = #isis_address{afi = AFI, address = Address, mask = Mask},
    case ets:lookup(State#state.interfaces, Name) of
	[I] -> NewA = delete_from_list(A, I#isis_interface.addresses),
	       ets:insert(State#state.interfaces, I#isis_interface{addresses = NewA}),
	       case is_valid_interface(I#isis_interface.name, State) of
		   true ->
		       case should_withdraw_route(R, State) of
			   true -> update_address_tlv(fun isis_protocol:delete_tlv/4,
						      AFI, Address, Mask, State);
			   _ -> State
		       end;
		   _ -> State
	       end;
	_ -> State
    end.

add_redistribute(#zclient_route{prefix = #zclient_prefix{afi = ipv4, address = Address,
						     mask_length = Mask},
				metric = Metric} = R, State) ->
    ets:insert(State#state.redistributed_routes, R),
    TLV = #isis_tlv_extended_ip_reachability{
	     reachability =
		 [#isis_tlv_extended_ip_reachability_detail{
		     prefix = Address,
		     mask_len = Mask,
		     metric = Metric,
		     up = true,
		     sub_tlv = []}]},
    update_frags(fun isis_protocol:update_tlv/4, TLV, 0, State);
add_redistribute(#zclient_route{prefix = #zclient_prefix{afi = ipv6, address = Address,
						     mask_length = Mask},
				metric = Metric, source = Source, nexthops = NH} = R, State)
  when is_list(NH) ->
    ets:insert(State#state.redistributed_routes, R),
    MaskLenBytes = erlang:trunc((Mask + 7) / 8),
    A = Address bsr (128 - Mask),
    SubTLV =
	case Source of
	    #zclient_prefix{afi = ipv6,
			    address = S,
			    mask_length = M} ->
		[#isis_subtlv_srcdst{prefix = S, prefix_length = M}];
	    _ -> []
	end,
    TLV = 
	#isis_tlv_ipv6_reachability{
	   reachability =
	       [#isis_tlv_ipv6_reachability_detail{
		   prefix = <<A:(MaskLenBytes * 8)>>, up = true,
		   mask_len = Mask, metric = Metric,
		   external = true,
		   sub_tlv = SubTLV}]
	  },
    update_frags(fun isis_protocol:update_tlv/4, TLV, 0, State);
add_redistribute(R, State) ->
    %% Ignoring this route
    io:format("Ignoring redistributed route: ~p~n", [R]),
    State.

delete_redistribute(#zclient_route{prefix = #zclient_prefix{afi = ipv4, address = Address,
							    mask_length = Mask},
				   metric = Metric} = R, State) ->
    ets:delete_object(State#state.redistributed_routes, R),
    TLV = 
     	#isis_tlv_extended_ip_reachability{
	   reachability = [#isis_tlv_extended_ip_reachability_detail{
			      prefix = Address,
			      mask_len = Mask,
			      metric = Metric,
			      up = true,
			      sub_tlv = []}]},
    case should_withdraw_route(R, State) of
	true -> update_frags(fun isis_protocol:delete_tlv/4, TLV, 0, State);
	_ -> State
    end;
delete_redistribute(#zclient_route{prefix = #zclient_prefix{afi = ipv6, address = Address,
							    mask_length = Mask},
				   metric = Metric, source = Source} = R, State) ->
    ets:delete_object(State#state.redistributed_routes, R),
    MaskLenBytes = erlang:trunc((Mask + 7) / 8),
    A = Address bsr (128 - Mask),
    SubTLV =
	case Source of
	    #zclient_prefix{afi = ipv6,
			    address = S,
			    mask_length = M} ->
		[#isis_subtlv_srcdst{prefix = S, prefix_length = M}];
	    _ -> []
	end,
    TLV = 
	#isis_tlv_ipv6_reachability{
	   reachability =
	       [#isis_tlv_ipv6_reachability_detail{
		   prefix = <<A:(MaskLenBytes * 8)>>, up = true,
		   mask_len = Mask, metric = Metric,
		   sub_tlv = SubTLV}]
	  },
    case should_withdraw_route(R, State) of
	true -> update_frags(fun isis_protocol:delete_tlv/4, TLV, 0, State);
	_ -> State
    end.

update_router_id(#zclient_prefix{afi = ipv4, address = A},
		 State) ->
    TLV = #isis_tlv_te_router_id{router_id = A},
    update_frags(fun isis_protocol:update_tlv/4, TLV, 0, State);
update_router_id(#zclient_prefix{afi = ipv6, address = _A},
		 State) ->
    %% Not sure what to do with v6 router-ids just yet..
    State.

update_frags(Updater, TLV, Node, State) ->
    F1 = Updater(TLV, Node, level_1, State#state.frags),
    %% F2 = Updater(TLV, Node, level_2, F1),
    State#state{frags = F1}.

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

delete_from_list(Item, List) ->
    lists:filter(fun(I) -> Item =/= I end, List).
		      
address_to_string(ipv4, Address) ->
    inet_parse:ntoa(
      erlang:list_to_tuple([X || <<X:8>> <= <<Address:32>>]));
address_to_string(ipv6, Address) when is_binary(Address) ->
    inet_parse:ntoa(
      erlang:list_to_tuple([X || <<X:16>> <= Address]));
address_to_string(ipv6, Address) when is_integer(Address) ->
    inet_parse:ntoa(
      erlang:list_to_tuple([X || <<X:16>> <= <<Address:128>>])).

address_to_string(#isis_address{afi = AFI, address = A, mask = M})
  when is_binary(A) ->
    SA = 
	case AFI of
	    ipv4 -> <<T:M>> = A,
		    T bsl (32 - M);
	    ipv6 -> <<T:M>> = A,
		    T bsl (128 - M)
	end,
    address_to_string(AFI, SA);
address_to_string(#isis_address{afi = AFI, address = A}) ->
    address_to_string(AFI, A).

address_apply_mask(ipv4, Address, Mask) ->
    (Address bsr (32 - Mask)) bsl (32 - Mask);
address_apply_mask(ipv6, Address, Mask) ->
    (Address bsr (128 - Mask)) bsl (128 - Mask).

%%%===================================================================
%% should_withdraw_route
%%
%% We should only remove the prefix from our TLVs if its not in either
%% the redist list, or the interface address lists.
%% In the case of #zclient_route{}, its been withdrawn from redist, so
%% check the connected set.
%% In the case of a #zclient_prefix{}, its a connected address being withdrawn
%% so check the redist bag.
%%%===================================================================
should_withdraw_route(#zclient_route{
			prefix = #zclient_prefix{
				   afi = AFI,
				   address = Address,
				   mask_length = Mask},
			source = undefined} = R, _State) ->
    AddressClean = address_apply_mask(AFI, Address, Mask),
    FindAddr = fun(_, true) -> true;
		  (#isis_address{afi = AAFI, address = AAddress, mask = AMask}, false) ->
		    AAddressClean = address_apply_mask(AAFI, AAddress, AMask),
		    AAFI =:= AFI andalso AAddressClean =:= AddressClean andalso AMask =:= Mask
	       end,
    CheckInt = fun(_, true) -> true;
		  (#isis_interface{addresses = A}, false) -> lists:foldl(FindAddr, false, A)
	       end,
    Result = not lists:foldl(CheckInt, false, isis_system:list_interfaces()),
    lager:error("should_withdraw_route ~p: ~p", [R, Result]),
    Result;
should_withdraw_route(#zclient_prefix{
			afi = AFI,
			address = Address,
			mask_length = Mask} = R, State) ->
    AddressClean = address_apply_mask(AFI, Address, Mask),
    Possibles = ets:lookup(State#state.redistributed_routes,
			   #zclient_prefix{afi = AFI, address = AddressClean, mask_length = Mask}),
    FilterFun = fun(#zclient_route{source = undefined}) -> true;
		   (_) -> false
		end,
    Result = not (length(lists:filter(FilterFun, Possibles)) > 0),
    lager:error("should_withdraw_route ~p: ~p", [R, Result]),    
    Result;
should_withdraw_route(_, _) ->
    true.

    

set_state([{lsp_lifetime, Value} | Vs], State) ->
    set_state(Vs, State#state{max_lsp_lifetime = Value});
set_state([_ | Vs], State) ->
    set_state(Vs, State);
set_state([], State) ->
    State.

extract_state(lsp_lifetime, State) ->
    State#state.max_lsp_lifetime;
extract_state(reachability, State) ->
    State#state.reachability;
extract_state(system_ids, State) ->
    State#state.system_ids;
extract_state(_, State) ->
    unknown_item.

dump_config_fields([{autoconf, true} | Fs], State) ->
    io:format("isis_system:set_state([{autoconf, true}]).~n", []),
    dump_config_fields(Fs, State);
dump_config_fields([{system_id, SID} | Fs], #state{system_id_set = true,
						   autoconf = false} = State) ->
    io:format("isis_system:set_system_id(~p).~n", [SID]),
    dump_config_fields(Fs, State);
dump_config_fields([{hostname, H} | Fs], State)
  when length(H) > 0 ->
    io:format("isis_system:set_hostname(~p).~n", [H]),
    dump_config_fields(Fs, State);
dump_config_fields([{areas, A} | Fs], State) ->
    lists:map(fun(Area) -> io:format("isis_system:add_area(~p).~n", [Area]) end,
	      A),
    dump_config_fields(Fs, State);
dump_config_fields([{max_lsp_lifetime, V} | Fs], State)
  when V =/= ?ISIS_MAX_LSP_LIFETIME ->
    io:format("isis_system:set_state([{lsp_lifetime, ~p}]).~n", [V]),
    dump_config_fields(Fs, State);
dump_config_fields([{interfaces, I} | Fs], State) ->
    dict:map(fun(Name, #isis_interface{enabled = true, pid = Pid}) ->
		     io:format("isis_system:add_interface(\"~s\").~n", [Name]),
		     isis_interface:dump_config(Pid);
		(_, _) -> false
	     end, I),
    dump_config_fields(Fs, State);
dump_config_fields([_ | Fs], State) ->
    dump_config_fields(Fs, State);
dump_config_fields([], _) ->
    ok.

dump_config(State) ->
    S = lists:zip(record_info(fields, state),
		  tl(erlang:tuple_to_list(State))),
    dump_config_fields(S, State).
