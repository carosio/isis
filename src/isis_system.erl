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
	 update_tlv/3, delete_tlv/3,
	 %% System Name handling
	 add_name/2, delete_name/1, lookup_name/1,
	 %% Handle System ID mapping
	 add_sid_addresses/2, delete_sid_addresses/2, dump_sid_addresses/0,
	 %% pseudonodes
	 allocate_pseudonode/2, deallocate_pseudonode/2,
	 %% Misc
	 address_to_string/2]).

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
		max_lsp_lifetime = ?ISIS_MAX_LSP_LIFETIME,
		pseudonodes :: dict(),  %% PID -> Pseudonode mapping
		interfaces :: dict(),   %% Our 'state' per interface
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
    gen_server:call(?MODULE, {set_interface, Name, Values}).

set_interface(Name, Level, Values) ->
    gen_server:call(?MODULE, {set_interface, Name, Level, Values}).

list_interfaces() ->
    gen_server:call(?MODULE, {list_interfaces}).

get_interface(Name) ->
    gen_server:call(?MODULE, {get_interface, Name}).

enable_level(Interface, level_1) ->
    gen_server:call(?MODULE, {enable_level, Interface, level_1});
enable_level(Interface, level_2) ->
    gen_server:call(?MODULE, {enable_level, Interface, level_2});
enable_level(_, _) ->
    io:format("Invalid level, should be either level_1 or level_2~n", []),
    bad_level.

disable_level(Interface, level_1) ->
    gen_server:call(?MODULE, {disable_level, Interface, level_1});
disable_level(Interface, level_2) ->
    gen_server:call(?MODULE, {disable_level, Interface, level_2});
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

update_tlv(TLV, Node, Level) ->
    %% io:format("Updating TLVs for node ~p ~p~n~p~n~p~n",
    %% 	      [Node, Level, TLV,
    %% 	      element(2, process_info(self(), backtrace))]),
    gen_server:cast(?MODULE, {update_tlv, TLV, Node, Level}).

delete_tlv(TLV, Node, Level) ->
    gen_server:cast(?MODULE, {delete_tlv, TLV, Node, Level}).

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

dump_sid_addresses() ->
    gen_server:call(?MODULE, {dump_sid_addresses}).

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
    State = #state{interfaces = dict:new(), system_ids = dict:new(),
		   pseudonodes = dict:new()},
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
		dict:store(Name, Interface#isis_interface{pid = undefined, enabled = false},
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

handle_call({set_interface, Name, Level, Values}, _From,
	    #state{interfaces = Interfaces} = State) ->
    case dict:find(Name, Interfaces) of
	{ok, Interface} ->
	    case is_pid(Interface#isis_interface.pid) of
		true -> isis_interface:set_level(
			  Interface#isis_interface.pid, Level, Values);
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

handle_call({clear_neighbors}, _From,
	    #state{interfaces = Interfaces} = State) ->
    dict:map(fun(_, I) ->
		     isis_interface:clear_neighbors(I#isis_interface.pid)
	     end, Interfaces),
    {reply, ok, State};
		     
handle_call({system_id}, _From,
	    #state{system_id = ID} = State) ->
    {reply, ID, State};
handle_call({set_system_id, undefined}, _From, State) ->
    isis_lspdb:set_system_id(level_1, undefined),
    isis_lspdb:set_system_id(level_2, undefined),
    NewState = purge_all_lsps(State),
    {reply, ok, NewState#state{system_id = undefined,
			       system_id_set = false}};
handle_call({set_system_id, Id}, _From, State)
  when is_binary(Id), byte_size(Id) =:= 6 ->
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

handle_call({dump_sid_addresses}, _From, State) ->
    {reply, State#state.system_ids, State};

handle_call({allocate_pseudonode, Pid, Level}, _From, State) ->
    {PN, NewState} = allocate_pseudonode(Pid, Level, State),
    {reply, PN, NewState};

handle_call({deallocate_pseudonode, Node, Level}, _From, State) ->
    {Reply, NewState} = deallocate_pseudonode(Node, Level, State),
    {reply, Reply, NewState};

handle_call({get_state, Item}, _From, State) ->
    {reply, extract_state(Item, State), State};

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
handle_cast({update_tlv, TLV, Node, Level},
	    #state{frags = Frags} = State) ->
    %% io:format("Updating tlv: ~p~n", [TLV]),
    NewFrags = isis_protocol:update_tlv(TLV, Node, Level, Frags),
    schedule_lsp_refresh(),
    isis_lspdb:schedule_spf(level_1),
    isis_lspdb:schedule_spf(level_2),
    {noreply, State#state{frags = NewFrags}};
handle_cast({delete_tlv, TLV, Node, Level},
	    #state{frags = Frags} = State) ->
    %% io:format("Deleting TLV: ~p~n", [TLV]),
    NewFrags = isis_protocol:delete_tlv(TLV, Node, Level, Frags),
    schedule_lsp_refresh(),
    {noreply, State#state{frags = NewFrags}};
handle_cast({add_sid, SID, Addresses}, #state{system_ids = IDs} = State) ->
    D1 = case dict:find(SID, IDs) of
	     error -> dict:store(SID, Addresses, IDs);
	     {ok, As} ->
		 S1 = sets:from_list(Addresses),
		 S2 = sets:from_list(As),
		 NewAs = sets:to_list(sets:union([S1, S2])),
		 dict:store(SID, NewAs, IDs)
	 end,
    isis_lspdb:schedule_spf(level_1),
    isis_lspdb:schedule_spf(level_2),
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
handle_cast({process_spf, {Level, Time, SPF}}, State) ->
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
    spf_summary:notify_subscribers({Time, Level, Table}),
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
		      isis_lspdb:flood_lsp(Level, dict:to_list(State#state.interfaces),
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
    isis_lspdb:flood_lsp(Level, dict:to_list(State#state.interfaces), LSP).

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

create_frag(PN, Level) ->
    #lsp_frag{level = Level,
	      pseudonode = PN}.

set_tlv_hostname(Name, State) ->
    TLV = #isis_tlv_dynamic_hostname{hostname = Name},
    L1Frags = isis_protocol:update_tlv(TLV, 0, level_1, State#state.frags),
    L2Frags = isis_protocol:update_tlv(TLV, 0, level_2, L1Frags),
    State#state{frags = L2Frags}.

allocate_pseudonode(Pid, Level, #state{frags = Frags} = State) ->
    F = fun(#lsp_frag{pseudonode = PN, level = L})
	      when Level =:= L ->
		{true, PN};
	   (_) -> false
	end,
    S1 = sets:from_list(lists:filtermap(F, Frags)),
    S2 = sets:from_list(lists:seq(1, 255)),
    L = sets:to_list(sets:subtract(S2, S1)),
    NewPN = lists:nth(1, lists:sort(L)),
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
    NewDict = dict:filter(G, State#state.pseudonodes),
    {ok, State#state{frags = NewFrags, pseudonodes = NewDict}}.

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
    NewFrags = purge_lsps(fun(_, _) -> true end, State),
    State#state{frags = NewFrags}.

%%--------------------------------------------------------------------
%% @doc
%%
%% Purge an LSP
%%
%% @end
%%--------------------------------------------------------------------
purge_lsp(Ref, LSP, State) ->
    case gen_server:call(Ref, {purge, LSP}) of
	{ok, PurgedLSP} ->
	    I = dict:to_list(State#state.interfaces),
	    isis_lspdb:flood_lsp(Ref, I, PurgedLSP),
	    ok;
	Result -> Result
    end.

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
		 isis_lspdb:set_system_id(level_1, Mac),
		 isis_lspdb:set_system_id(level_2, Mac),
		 NextState =
		     set_tlv_hostname(DynamicName, State#state{system_id = Mac,
							system_id_set = true}),
		 force_refresh_lsp(NextState),
		 NextState
	end,
    %% Enable interface and level1...
    State2 = do_enable_interface(I, State1),
    Interface = dict:fetch(Name, State2#state.interfaces),
    do_enable_level(Interface, level_1),
    isis_interface:set_level(Interface#isis_interface.pid, level_1,
			     [{encryption, text, <<"isis-autoconf">>},
			      {metric, ?DEFAULT_AUTOCONF_METRIC},
			      %%{priority, ?DEFAULT_PRIORITY}]),
			      {priority, 4}]),
    State2;
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
    I = case dict:is_key(Name, State#state.interfaces) of
	    true ->
		dict:fetch(Name, State#state.interfaces);
	    _ ->
		#isis_interface{name = Name}
	end,
    A = #isis_address{afi = AFI, address = Address, mask = Mask},
    NewA = add_to_list(A, I#isis_interface.addresses),
    NewD = dict:store(Name, I#isis_interface{addresses = NewA}, State#state.interfaces),
    NewState = update_address_tlv(fun isis_protocol:update_tlv/4,
				  AFI, Address, Mask, State),
    NewState#state{interfaces = NewD}.

delete_address(#zclient_prefix{afi = AFI, address = Address, mask_length = Mask},
	       Name, State) ->
    A = #isis_address{afi = AFI, address = Address, mask = Mask},
    case dict:is_key(Name, State#state.interfaces) of
	true ->
	    I = dict:fetch(Name, State#state.interfaces),
	    NewA = delete_from_list(A, I#isis_interface.addresses),
	    NewD = dict:store(Name, I#isis_interface{addresses = NewA}, State#state.interfaces),
	    NewState = update_address_tlv(fun isis_protocol:delete_tlv/4,
					  AFI, Address, Mask, State),
	    NewState#state{interfaces = NewD};
	_ -> State
    end.

add_redistribute(#zclient_route{prefix = #zclient_prefix{afi = ipv4, address = Address,
						     mask_length = Mask},
				metric = Metric}, State) ->
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
				metric = Metric, source = Source}, State) ->
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
    update_frags(fun isis_protocol:update_tlv/4, TLV, 0, State).

delete_redistribute(#zclient_route{prefix = #zclient_prefix{afi = ipv4, address = Address,
							    mask_length = Mask},
				   metric = Metric}, State) ->
    TLV = 
     	#isis_tlv_extended_ip_reachability{
	   reachability = [#isis_tlv_extended_ip_reachability_detail{
			      prefix = Address,
			      mask_len = Mask,
			      metric = Metric,
			      up = true,
			      sub_tlv = []}]},
    update_frags(fun isis_protocol:delete_tlv/4, TLV, 0, State);
delete_redistribute(#zclient_route{prefix = #zclient_prefix{afi = ipv6, address = Address,
							    mask_length = Mask},
				   metric = Metric}, State) ->
    MaskLenBytes = erlang:trunc((Mask + 7) / 8),
    A = Address bsr (128 - Mask),
    TLV = 
	#isis_tlv_ipv6_reachability{
	   reachability =
	       [#isis_tlv_ipv6_reachability_detail{
		   prefix = <<A:(MaskLenBytes * 8)>>, up = true,
		   mask_len = Mask, metric = Metric,
		   sub_tlv = []}]
	  },
    update_frags(fun isis_protocol:delete_tlv/4, TLV, 0, State).

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
      erlang:list_to_tuple([X || <<X:8>> <= Address]));
address_to_string(ipv6, Address) when is_integer(Address) ->
    inet_parse:ntoa(
      erlang:list_to_tuple([X || <<X:8>> <= <<Address:128>>])).

set_state([{lsp_lifetime, Value} | Vs], State) ->
    set_state(Vs, State#state{max_lsp_lifetime = Value});
set_state([_ | Vs], State) ->
    set_state(Vs, State);
set_state([], State) ->
    State.

extract_state(lsp_lifetime, State) ->
    State#state.max_lsp_lifetime;
extract_state(_, State) ->
    unknown_item.
