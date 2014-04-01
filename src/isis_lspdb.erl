%%%-------------------------------------------------------------------
%%% @author Rick Payne <rickp@rossfell.co.uk>
%%% @copyright (C) 2014, Rick Payne
%%% @doc
%%% LSPDB - maintains the linkstate database for LSP fragments for
%%% a given isis_system.
%%%
%%% @end
%%% Created : 24 Jan 2014 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------
-module(isis_lspdb).

-behaviour(gen_server).

-include("isis_system.hrl").
-include("isis_protocol.hrl").
-include_lib("stdlib/include/ms_transform.hrl").

%% API
-export([start_link/1, get_db/1,
	 lookup_lsps/2, store_lsp/2, delete_lsp/2, purge_lsp/2,
	 lookup_lsps_by_node/2,
	 summary/2, range/3,
	 replace_tlv/3, update_reachability/3,
	 flood_lsp/3, bump_lsp/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE).

-record(state, {db,               %% The ETS table we store our LSPs in
		name_db,          %% Dict for name mapping (may need this as ETS?)
		level,            %% Our level
	        expiry_timer,     %% We expire LSPs based on this timer
		spf_timer = undef, %% Dijkestra timer
		hold_timer        %% SPF Hold timer
	       }).

%%%===================================================================
%%% API
%%%===================================================================
%%--------------------------------------------------------------------
%% @doc
%%
%% Store an LSP into the database. If we're replacing an existing LSP,
%% check to see if we need to schedule an SPF run, otherwise we
%% schedule one anyway.
%%
%% @end
%%--------------------------------------------------------------------
store_lsp(Ref, LSP) ->
    gen_server:call(Ref, {store, LSP}).

%%--------------------------------------------------------------------
%% @doc
%%
%% Given an LSP-Id, delete its from the LSP DB
%%
%% @end
%%--------------------------------------------------------------------
delete_lsp(Ref, LSP) ->
    gen_server:call(Ref, {delete, LSP}).

bump_lsp(Ref, LSP) ->
    gen_server:cast(Ref, {bump, Ref, LSP}).

%%--------------------------------------------------------------------
%% @doc
%%
%% Purge an LSP
%%
%% @end
%%--------------------------------------------------------------------
purge_lsp(Ref, LSP) ->
    case gen_server:call(Ref, {purge, LSP}) of
	{ok, PurgedLSP} ->
	    D = isis_system:list_interfaces(),
	    I = dict:to_list(D),
	    flood_lsp(Ref, I, PurgedLSP),
	    ok;
	Result -> Result
    end.
	     

%%--------------------------------------------------------------------
%% @doc
%%
%% Return the ETS database handle, as we allow concurrent reads. All
%% writes come via the gen_server though.
%%
%% @end
%%--------------------------------------------------------------------
get_db(Ref) ->
    gen_server:call(Ref, {get_db}).

%%--------------------------------------------------------------------
%% @doc
%%
%% Lookup a list of LSP. This is looked up directly from the process
%% that calls this, rather than via the gen_server
%%
%% The resulting list has had the remaining_lifetime updated, but not
%% filter.
%%
%% @end
%%--------------------------------------------------------------------
-spec lookup_lsps([binary()], atom()) -> [isis_lsp()].
lookup_lsps(Ids, DB) ->
    lookup(Ids, DB).

%%--------------------------------------------------------------------
%% @doc
%%
%% Extract a summary of the LSPs in the database - useful for building
%% CSNP messages, for instance. This is looked up directly from the
%% process that calls this, rather than via the gen_server
%% 
%% @end
%%--------------------------------------------------------------------
summary(Args, DB) ->
    lsp_summary(Args, DB).

%%--------------------------------------------------------------------
%% @doc
%%
%% Extract information for all LSPs that lie within a given range as
%% long as they have not exceeded their lifetime. For instance, if we
%% receive a CSNP with a start and end LSP-id, we can extract the
%% summary and then compare that with the values in the TLV of the
%% CSNP.
%% 
%% @end
%%-------------------------------------------------------------------
-spec range(binary(), binary(), atom() | integer()) -> list().
range(Start_ID, End_ID, DB) ->
    lsp_range(Start_ID, End_ID, DB).

%%--------------------------------------------------------------------
%% @doc
%%
%% For a given LSP, look it up, search the TLV for a matching TLV and
%% replace it with the provided TLV, bump the sequence number and
%% re-flood...
%% 
%% @end
%%-------------------------------------------------------------------
-spec replace_tlv(atom(), isis_tlv(), binary()) -> ok.
replace_tlv(Level, TLV, LSP) ->
    DB = isis_lspdb:get_db(Level),
    case lookup_lsps([LSP], DB) of
	[L] -> NewTLV = replace_tlv(L#isis_lsp.tlv, TLV),
	       NewLSP = L#isis_lsp{tlv = NewTLV},
	       CSum = isis_protocol:checksum(NewLSP),
	       bump_lsp(Level, NewLSP#isis_lsp{checksum = CSum}),
	       ok;
	_ -> error
    end.

%%--------------------------------------------------------------------
%% @doc
%%
%% Add/Del reachability to the TLVs
%%
%% @end
%%--------------------------------------------------------------------
update_reachability({AddDel, ER}, Level, #isis_lsp{tlv = TLVs} = LSP) ->
    Worker =
	fun(#isis_tlv_extended_reachability{reachability = R}, Flood) ->
		{F, NewER} = update_eir(AddDel, ER, R),
		case Flood of
		    true ->
			{#isis_tlv_extended_reachability{reachability = NewER}, true};
		    _ -> {#isis_tlv_extended_reachability{reachability = NewER}, F}
		end;
	   (A, B) -> {A, B}
	end,
    {NewTLVs, Flood} = lists:mapfoldl(Worker, false, TLVs),
    io:format("Was: ~p~nNow: ~p~n", [TLVs, NewTLVs]),
    case Flood of
	true ->
	    NewLSP = LSP#isis_lsp{tlv = NewTLVs},
	    bump_lsp(Level, NewLSP);
	_ -> ok
    end.

%%--------------------------------------------------------------------
%% @doc
%%
%% Bump sequence number and flood.
%%
%% @end
%%--------------------------------------------------------------------
bump_an_lsp(Level, L, State) ->
    ets:insert(State#state.db,
	       L#isis_lsp{
		 sequence_number = (L#isis_lsp.sequence_number + 1),
		 remaining_lifetime = 1200,
		 last_update = isis_protocol:current_timestamp()}),
    D = isis_system:list_interfaces(),
    I = dict:to_list(D),
    flood_lsp(Level, I, L).

purge(LSP, State) ->
    case ets:lookup(State#state.db, LSP) of
	[OldLSP] ->
	    PurgedLSP = OldLSP#isis_lsp{tlv = [], remaining_lifetime = 0, checksum = 0,
					last_update = isis_protocol:current_timestamp()},
	    ets:insert(State#state.db, PurgedLSP),
	    {ok, PurgedLSP};
	_ -> missing_lsp
    end.
	    

flood_lsp(Level, Interfaces, LSP) ->
    case isis_protocol:encode(LSP) of
	{ok, Packet, Size} ->
	    Sender = fun({_N, #isis_interface{pid = P}}) ->
			     case is_pid(P) of
				 true -> isis_interface:send_pdu(P, Packet, Size, Level);
				 _ -> ok
			     end
		     end,
	    lists:map(Sender, Interfaces),
	    ok;
	_ -> error
    end.
		     

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @spec start_link(list()) -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link([{table, Table_Id}] = Args) ->
    gen_server:start_link({local, Table_Id}, ?MODULE, Args, []).

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
init([{table, Table_ID}]) ->
    process_flag(trap_exit, true),
    DB = ets:new(Table_ID, [ordered_set, {keypos, #isis_lsp.lsp_id}]),
    NameDB = dict:new(),
    Timer = start_timer(expiry, #state{expiry_timer = undef}),
    {ok, #state{db = DB, name_db = NameDB, level = Table_ID, 
		expiry_timer = Timer, spf_timer = undef}}.

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
handle_call({get_db}, _From, State) ->
    {reply, State#state.db, State};

handle_call({store, #isis_lsp{} = LSP},
	    _From, State) ->
    OldLSP = ets:lookup(State#state.db, LSP#isis_lsp.lsp_id),
    NewState = 
	case spf_type_required(OldLSP, LSP) of
	    full -> schedule_spf(full, State);
	    partial -> schedule_spf(partial, State);
	    incremental -> schedule_spf(incremental, State);
	    none -> State
	end,
    Result = ets:insert(NewState#state.db, LSP),
    NameTLV = isis_protocol:filter_tlvs(isis_tlv_dynamic_hostname, LSP#isis_lsp.tlv),
    case length(NameTLV) > 0 of
	true -> NameT = lists:nth(1, NameTLV),
		<<SysID:6/binary, _:16>> = LSP#isis_lsp.lsp_id,
		isis_system:add_name(SysID, NameT#isis_tlv_dynamic_hostname.hostname);
	_ -> ok
    end,
    {reply, Result, NewState};

handle_call({delete, LSP},
	    _From, State) ->
    {reply, ets:delete(State#state.db, LSP), State};

handle_call({purge, LSP}, _From, State) ->
    Result = purge(LSP, State),
    {reply, Result, State};

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
handle_cast({bump, Level, LSP}, State) ->
    bump_an_lsp(Level, LSP, State),
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
handle_info({timeout, _Ref, expiry}, State) ->
    erlang:cancel_timer(State#state.expiry_timer),
    expire_lsps(State),
    Timer = start_timer(expiry, State),
    {noreply, State#state{expiry_timer = Timer}};
handle_info({timeout, _Ref, {run_spf, _Type}}, State) ->
    %% Ignoring type for now...
    erlang:cancel_timer(State#state.spf_timer),
    %% Dijkestra...
    {Time, SPF} = timer:tc(fun() -> do_spf(State) end),
    io:format("SPF run for ~p took ~p microseconds~n",
	      [State#state.level, Time]),
    isis_system:process_spf(SPF),
    {noreply, State#state{spf_timer = undef}};
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
%%--------------------------------------------------------------------
%% @private
%% @doc
%%
%% Take a list of LSP-IDs and look them up in the database. Fixup the
%% lifetime, but do not filter for zero or negative lifetimes...
%%
%% @end
%%--------------------------------------------------------------------
-spec lookup([binary()], atom()) -> [isis_lsp()].
lookup(IDs, DB) ->
    lists:filtermap(fun(LSP) ->
		      case ets:lookup(DB, LSP) of
			  [L] -> {true, isis_protocol:fixup_lifetime(L)};
			  [] -> false
		      end
	      end, IDs).

%%--------------------------------------------------------------------
%% @doc
%%
%% Take a list of LSP-IDs and look them up in the database. Fixup the
%% lifetime, but do not filter for zero or negative lifetimes...
%%
%% @end
%%--------------------------------------------------------------------
-spec lookup_lsps_by_node(binary(), atom()) -> [isis_lsp()].
lookup_lsps_by_node(Node, DB) ->
    F = fun(#isis_lsp{lsp_id = <<LSP_Id:7/binary, _Frag:8>>} = L, Ls)
	      when LSP_Id =:= Node ->
		[L] ++ Ls;
	   (_, Ls) -> Ls
	end,
    ets:foldl(F, [], DB).

%%--------------------------------------------------------------------
%% @private
%% @doc
%%
%% Summarise the database (for CSNP generation). Returned format is:
%% {Key, Sequence Number, Checksum, Remaining Lifetime}
%%
%% @end
%%--------------------------------------------------------------------
lsp_summary({start, Count}, DB) when Count > 0 ->
    Now = isis_protocol:current_timestamp(),
    F = ets:fun2ms(fun(#isis_lsp{lsp_id = LSP_Id, remaining_lifetime = L,
				 sequence_number = N,
				 last_update = U, checksum = C})
		      when (L - (Now - U)) > -?DEFAULT_LSP_AGEOUT ->
			   {LSP_Id, N, C, L - (Now - U)} end),
    case ets:select(DB, F, Count) of
	{Results, Continuation} -> {Results, Continuation};
	'$end_of_table' -> {[], '$end_of_table'}
    end;
lsp_summary({continue, Continuation}, _DB) ->
    case ets:select(Continuation) of
	{Results, Next} -> {Results, Next};
	'$end_of_table' -> {[], '$end_of_table'}
    end;
lsp_summary(_, _) ->
    {[], '$end_of_table'}.


%%--------------------------------------------------------------------
%% @private
%% @doc
%%
%% Summarise a range of the database. Format returned is:
%% {LSP ID, Sequence Number, Checksum, Remaining Lifetime}
%%
%% @end
%%--------------------------------------------------------------------
-spec lsp_range(binary(), binary(), atom() | integer()) ->
		       [{binary(), integer(), integer(), integer()}].
lsp_range(Start_ID, End_ID, DB) ->
    Now = isis_protocol:current_timestamp(),
    F = ets:fun2ms(fun(#isis_lsp{lsp_id = LSP_Id, remaining_lifetime = L,
				 last_update = U, sequence_number = N, checksum = C})
		      when LSP_Id >= Start_ID, LSP_Id =< End_ID, (L - (Now - U)) > 0,
			   (L - (Now - U)) > 0 ->
			   {LSP_Id, N, C, L - (Now - U)} end),
    ets:select(DB, F).

%%--------------------------------------------------------------------
%% @private
%% @doc
%%
%% Remove any LSP from the database that is ?DEFAULT_LSP_AGEOUT
%% seconds older than the lifetime allowed.
%%
%% @end
%%--------------------------------------------------------------------
-spec expire_lsps(tuple()) -> integer().
expire_lsps(#state{db = DB}) ->
    Now = isis_protocol:current_timestamp(),
    F = ets:fun2ms(fun(#isis_lsp{lsp_id = LSP_Id, remaining_lifetime = L,
				 last_update = U, sequence_number = N, checksum = C})
		      when (L - (Now - U)) < -?DEFAULT_LSP_AGEOUT ->
			   true end),
    ets:select_delete(DB, F).

%%--------------------------------------------------------------------
%% @private
%% @doc
%%
%% Compare the previous LSP with the new LSP and depending on what has
%% changed, and figure out what sort of spf run is required.
%% SPF Type can be:
%%    full - a full dijkestra run is required
%%
%% @end
%%--------------------------------------------------------------------
-spec spf_type_required([isis_lsp()], isis_lsp()) -> full | partial | incremental | none.
spf_type_required([], LSP) ->
    L = isis_protocol:filter_tlvs(isis_tlv_extended_reachability,
				  LSP#isis_lsp.tlv),
    case length(L) >= 1 of
	true -> full;
	_ -> none
    end;
spf_type_required([OldLSP], NewLSP) ->
    OldR = isis_protocol:filter_tlvs(isis_tlv_extended_reachability,
				     OldLSP#isis_lsp.tlv),
    NewR = isis_protocol:filter_tlvs(isis_tlv_extended_reachability,
				     NewLSP#isis_lsp.tlv),
    case OldR =:= NewR of
	true -> partial;
	_ -> full
    end.

%%--------------------------------------------------------------------
%% @private
%% @doc
%%
%% Schedule an SPF of the appropriate type...
%%
%% @end
%%--------------------------------------------------------------------
-spec schedule_spf(full | partial | incremental, tuple()) -> tuple().
schedule_spf(Type, #state{spf_timer = undef} = State) ->
    Timer = erlang:start_timer(
	      isis_protocol:jitter(?ISIS_SPF_DELAY, 10),
	      self(), {run_spf, Type}),
    State#state{spf_timer = Timer};
schedule_spf(_, State) ->
    %% Timer already primed...
    State.

-spec start_timer(atom(), tuple()) -> integer() | ok.
start_timer(expiry, #state{expiry_timer = T}) when T =/= undef ->
    erlang:start_timer((?DEFAULT_EXPIRY_TIMER * 1000), self(), expiry);
start_timer(spf, #state{spf_timer = S}) when S =/= undef ->
    erlang:start_timer((?DEFAULT_SPF_DELAY * 1000), self(), spf);
start_timer(_, _) ->
    ok.

%%--------------------------------------------------------------------
%% @doc
%%
%% Simplistic replacement of an existing TLV with a new TLV. If you
%% want to do something cleverer with regards to replacing parts of a
%% TLV, then you need to write some more code..
%%
%% @end
%%--------------------------------------------------------------------
-spec replace_tlv([isis_tlv()], isis_tlv()) -> [isis_tlv()].
replace_tlv(TLVs, TLV) ->
    Type = element(1, TLV),
    F = fun(A, Found) ->
		case element(1, A) =:= Type of
		    true -> {TLV, true};
		    _ -> {A, Found}
		end
	end,
    case lists:mapfoldl(F, false, TLVs) of
	{L, true} -> L;
	{L, _} -> [TLV] ++ L
    end.

-spec update_eir(atom(), isis_tlv_extended_reachability_detail(),
		 [isis_tlv_extended_reachability_detail()]) ->
			{atom(), [isis_tlv_extended_reachability_detail()]}.
update_eir(add,
	   #isis_tlv_extended_reachability_detail{neighbor = N} = UpdatedER, R) ->
    %% Iterate the list, if we find it - has it changed? We don't want
    %% to flood if the EIR for this neighbor has not changed....
    Replacer =
	fun(ExistingER, _) when ExistingER =:= UpdatedER ->
		{UpdatedER, {true, false}};
	   (#isis_tlv_extended_reachability_detail{neighbor = T}, _) when T =:= N ->
		{UpdatedER, {true, true}};
	   (E, Acc) -> {E, Acc}
	end,
    {NewER, {Found, Modified}} = lists:mapfoldl(Replacer, {false, false}, R),
    io:format("Was: ~p~nNow: ~p~n", [R, NewER]),
    Result = 
	case {NewER, {Found, Modified}} of
	    {NewER, {true, true}} -> {true, NewER};
	    {NewER, {true, false}} -> {false, NewER};
	    {NewER, {false, false}} -> {true, NewER ++ [UpdatedER]}
	end,
    io:format("Returning: ~p~n", [Result]),
    Result;
update_eir(del,
	   #isis_tlv_extended_reachability_detail{neighbor = N}, R) ->
    Filter =
	fun(#isis_tlv_extended_reachability_detail{neighbor = T}) when T =:= N ->
		false;
	   (_) -> true
	end,
    New = lists:filter(Filter, R),
    Flood = length(New) =/= length(R),
    {Flood, New}.

do_spf(State) ->	    
    SysID = <<(isis_system:system_id())/binary, 0:8>>,
    Build_Graph =
	fun({From, To}, Metric, G) ->
		graph:add_vertex(G, From),
		graph:add_vertex(G, To),
		graph:add_edge(G, From, To, Metric),
		G
	end,
    Edges = populate_links(State),
    Graph = graph:empty(directed),
    dict:fold(Build_Graph, Graph, Edges),
    DResult = dijkstra:run(Graph, SysID),
    RoutingTableF = 
	fun({Node, {Metric, Nodes}}) when length(Nodes) >= 2 ->
		Prefixes = lookup_prefixes(Node, State),
		Nexthop = get_nexthop(lists:nth(2, Nodes)),
		{true, {Nexthop, Metric, Prefixes}};
	   ({_, {_, _}}) -> false;
	   ({_, unreachable}) -> false
	end,
    RoutingTable = lists:filtermap(RoutingTableF, DResult),
    RoutingTable.

lookup_prefixes(Node, State) ->
    LSPs = lookup_lsps_by_node(Node, State#state.db),
    TLVs = lists:foldl(fun(L, Ts) ->
			     isis_protocol:filter_tlvs(
			       [isis_tlv_ip_internal_reachability,
				isis_tlv_extended_ip_reachability,
				isis_tlv_ipv6_interface_address,
				isis_tlv_ipv6_reachability],
			       L#isis_lsp.tlv)
				   ++ Ts
		       end, [], LSPs),
    IPs = lists:foldl(fun extract_ip_addresses/2, [], TLVs),
    IPs.
    

get_nexthop(Node) ->
    Node.

%%--------------------------------------------------------------------
%% @private
%% @doc
%%
%% Convert the LSP database into a set of {From, To}, Metric values
%% stored in a dict. We'll prefer the metrics from the
%% extended-reachability TLV over those in a standard reachability
%% TLV.
%%
%% At the end, for every {A, B} entry, there should be a {B, A} entry,
%% otherwise we should not use the link.
%%
%% @end
%%--------------------------------------------------------------------
populate_dict(D, From, {To, Metric}) ->
    NewD = 
	case dict:find({From, To}, D) of
	    error -> dict:store({From, To}, Metric, D);
	    {ok, _Value} -> D
	end,
    NewD;
populate_dict(D, From, [#isis_tlv_extended_reachability_detail{
			 neighbor = N, metric = M} | Ts]) ->
    NewD = populate_dict(D, From, {N, M}),
    populate_dict(NewD, From, Ts);
populate_dict(D, From, [#isis_tlv_is_reachability_detail{
			   neighbor = N, default = M} | Ts]) ->
    NewD = populate_dict(D, From, {N, M#isis_metric_information.metric}),
    populate_dict(NewD, From, Ts);
populate_dict(D, From, [#isis_tlv_is_reachability{is_reachability = R} | Ts]) ->
    NewD = populate_dict(D, From, R),
    populate_dict(NewD, From, Ts);
populate_dict(D, From, [#isis_tlv_extended_reachability{reachability = R} | Ts]) ->
    NewD = populate_dict(D, From, R),
    populate_dict(NewD, From, Ts);
populate_dict(D, _From, []) ->
    D.

extract_reachability(D, From, TLV) ->
    Extendeds = isis_protocol:filter_tlvs(isis_tlv_extended_reachability, TLV),
    Normals = isis_protocol:filter_tlvs(isis_tlv_is_reachability, TLV),
    D1 = populate_dict(D, From, Extendeds),
    D2 = populate_dict(D1, From, Normals),
    D2.

populate_links(State) ->    
    Reachability =
	fun(L, Acc) ->
		<<Sys:7/binary, _/binary>> = L#isis_lsp.lsp_id,
		extract_reachability(Acc, Sys, L#isis_lsp.tlv)
	end,
    Edges = ets:foldl(Reachability, dict:new(), State#state.db),
    Edges.

extract_ip_addresses(#isis_tlv_ip_internal_reachability{ip_reachability = R}, Ts) ->
    lists:map(fun(#isis_tlv_ip_internal_reachability_detail{ip_address = A, subnet_mask = M,
							    default = #isis_metric_information{
									 metric = Metric
									}}) ->
		      %% MAP Subnet mask to a len here!
		      #isis_address{afi = ipv4, address = A, mask = M, metric = Metric}
	      end, R)
	++ Ts;
extract_ip_addresses(#isis_tlv_extended_ip_reachability{reachability = R}, Ts) ->
    lists:map(fun(#isis_tlv_extended_ip_reachability_detail{prefix = P, mask_len = M, metric = Metric}) ->
		      #isis_address{afi = ipv4, address = P, mask = M, metric = Metric}
	      end, R)
	++ Ts;
extract_ip_addresses(#isis_tlv_ipv6_reachability{prefix = P, mask_len = M, metric = Metric}, Ts) ->
    [#isis_address{afi = ipv6, address = P, mask = M, metric = Metric}] ++ Ts.
