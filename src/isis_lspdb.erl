%%%-------------------------------------------------------------------
%%% @author Rick Payne <rickp@rossfell.co.uk>
%%% @copyright (C) 2014, Alistair Woodman, California USA <awoodman@netdef.org>
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
	 lookup_lsps/2, store_lsp/2, delete_lsp/2, flood_lsp/3,
	 lookup_lsps_by_node/2,
	 summary/2, range/3,
	 replace_tlv/3, update_reachability/3,
	 schedule_spf/2,
	 links/1,
	 clear_db/1,
	 set_system_id/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE).

-record(state, {db,               %% The ETS table we store our LSPs in
		name_db,          %% Dict for name mapping (may need this as ETS?)
		level,            %% Our level
		system_id = undefined, %% Our system id
	        expiry_timer = undef,  %% We expire LSPs based on this timer
		spf_timer = undef, %% Dijkestra timer
		spf_reason = "",
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

%%--------------------------------------------------------------------
%% @doc
%%
%% Given an LSP-Id, delete its from the LSP DB
%%
%% @end
%%--------------------------------------------------------------------
clear_db(Ref) ->
    gen_server:call(Ref, {clear_db}).

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
%% Inform the lsp-db about the system id, so it doesn't need to request it
%% from isis_system..
%%
%% @end
%%--------------------------------------------------------------------
set_system_id(Ref, Id) ->
    gen_server:cast(Ref, {set_system_id, Id}).

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
    case Flood of
	true ->
	    NewLSP = LSP#isis_lsp{tlv = NewTLVs};
	_ -> ok
    end.

%%--------------------------------------------------------------------
%% @doc
%%
%% Purge an LSP
%%
%% @end
%%--------------------------------------------------------------------
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
	    Sender = fun(#isis_interface{pid = P}) ->
			     case is_pid(P) of
				 true -> isis_interface:send_pdu(P, lsp, Packet, Size, Level);
				 _ -> ok
			     end
		     end,
	    lists:map(Sender, Interfaces),
	    ok;
	_ -> error
    end.

links(DB) ->
    populate_links(DB).

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @spec start_link(list()) -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link([{table, Table_Id}] = Args) ->
    gen_server:start_link({local, Table_Id}, ?MODULE, Args, []).

%%--------------------------------------------------------------------
%% @doc
%%
%% Schedule an SPF run for a given LSP-DB
%%
%% @spec start_link(list()) -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
schedule_spf(Ref, Reason) ->
    gen_server:cast(Ref, {schedule_spf, Reason}).

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
    Timer = start_timer(expiry, #state{}),
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
    <<ID:6/binary, PN:8, Frag:8>> = LSP#isis_lsp.lsp_id,
    Reason = lists:flatten(
	       io_lib:format("LSP ~s.~2.16.0B-~2.16.0B updated",
			     [isis_system:lookup_name(ID), PN, Frag])),
    %% io:format("SPF type required: ~p~nOld: ~p~nNew: ~p~n",
    %% 	      [spf_type_required(OldLSP, LSP), OldLSP, LSP]),
    NewState = 
	case spf_type_required(OldLSP, LSP) of
	    full -> schedule_spf(full, Reason, State);
	    partial -> schedule_spf(partial, Reason, State);
	    incremental -> schedule_spf(incremental, Reason, State);
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

handle_call({clear_db}, _From, State) ->
    ets:delete_all_objects(State#state.db),
    {reply, ok, State};

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
handle_cast({schedule_spf, Reason}, State) ->
    {noreply, schedule_spf(full, Reason, State)};
handle_cast({set_system_id, ID}, State) ->
    {noreply, State#state{system_id = ID}};
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
    NewState = expire_lsps(State),
    Timer = start_timer(expiry, NewState#state{expiry_timer = undef}),
    {noreply, NewState#state{expiry_timer = Timer}};
handle_info({timeout, _Ref, {run_spf, _Type}}, State) ->
    %% Ignoring type for now...
    erlang:cancel_timer(State#state.spf_timer),
    %% Dijkestra...
    {Time, SPF} = timer:tc(fun() -> do_spf(State#state.system_id, State) end),
    isis_system:process_spf({State#state.level, Time, SPF,
			     State#state.spf_reason}),
    {noreply, State#state{spf_timer = undef, spf_reason = ""}};
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
    schedule_spf(full, "Code update", State),
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
		      when LSP_Id >= Start_ID, LSP_Id =< End_ID ->
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
expire_lsps(#state{db = DB, level = Level} = State) ->
    Now = isis_protocol:current_timestamp(),
    F = ets:fun2ms(fun(#isis_lsp{lsp_id = LSP_Id, remaining_lifetime = L,
				 last_update = U, sequence_number = N})
			 when (L - (Now - U)) < -?DEFAULT_LSP_AGEOUT ->
			   LSP_Id
		   end),
    Deletes = ets:select(DB, F),
    LSPs = 
	lists:foldl(
	  fun(D, Acc) ->
		  ets:delete(DB, D),
		  <<SID:6/binary, PN:8, Frag:8>> = D,
		  Acc ++ lists:flatten(io_lib:format("~4.16.0B.~4.16.0B.~4.16.0B-~2.16.0B-~2.16.0B ",
						     [X || <<X:16>> <= SID] ++ [PN, Frag]))
	  end, "", Deletes),
    case length(Deletes) of
	0 -> lager:info("Expired 0 ~p LSPs~n", [Level]),
	     State;
	C -> lager:info("Expired ~B ~p LSPs (~s)~n", [C, Level, LSPs]),
	     schedule_spf(full, "LSPs deleted", State)
    end.

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
    L = isis_protocol:filter_tlvs([isis_tlv_is_reachability,
				   isis_tlv_extended_reachability],
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
-spec schedule_spf(full | partial | incremental, string(), tuple()) -> tuple().
schedule_spf(Type, Reason, #state{spf_timer = undef} = State) ->
    lager:warning("Scheduling ~p SPF due to ~s~n", [State#state.level, Reason]),
    Timer = erlang:start_timer(
	      isis_protocol:jitter(?ISIS_SPF_DELAY, 10),
	      self(), {run_spf, Type}),
    State#state{spf_timer = Timer, spf_reason = Reason};
schedule_spf(_, Reason, State) ->
    %% Timer already primed...
    lager:warning("SPF required due to ~s (but already scheduled)~n", [Reason]),
    State.

-spec start_timer(atom(), tuple()) -> integer() | ok.
start_timer(expiry, #state{expiry_timer = T}) when T =:= undef ->
    erlang:start_timer(isis_protocol:jitter((?DEFAULT_EXPIRY_TIMER * 1000), 10), self(), expiry);
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
    Result = 
	case {NewER, {Found, Modified}} of
	    {NewER, {true, true}} -> {true, NewER};
	    {NewER, {true, false}} -> {false, NewER};
	    {NewER, {false, false}} -> {true, NewER ++ [UpdatedER]}
	end,
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

do_spf(undefined, _State) ->
    [];
do_spf(SID, State) ->
    SysID = <<SID:6/binary, 0:8>>,
    Build_Graph =
	fun({From, To}, Metric, G) ->
		graph:add_vertex(G, From),
		graph:add_vertex(G, To),
		graph:add_edge(G, From, To, Metric),
		G
	end,
    Edges = populate_links(State#state.db),
    Graph = graph:empty(directed),
    dict:fold(Build_Graph, Graph, Edges),
    DResult = dijkstra:run(Graph, SysID),
    RoutingTableF = 
	fun({Node, {Metric, Nodes}}) when length(Nodes) >= 2 ->
		Prefixes = lookup_prefixes(Node, State),
		Nexthop = get_nexthop(Nodes),
		{true, {Node, Nexthop, Metric, Prefixes, Nodes}};
	   ({_, {_, _}}) -> true;
	   ({_, unreachable}) -> true
	end,
    graph:del_graph(Graph),
    RoutingTable = lists:filtermap(RoutingTableF, DResult),
    RoutingTable.

lookup_prefixes(Node, State) ->
    LSPs = lookup_lsps_by_node(Node, State#state.db),
    TLVs = lists:foldl(fun(L, Ts) ->
			     isis_protocol:filter_tlvs(
			       [isis_tlv_ip_internal_reachability,
				isis_tlv_extended_ip_reachability,
				isis_tlv_ipv6_reachability],
			       L#isis_lsp.tlv)
				   ++ Ts
		       end, [], LSPs),
    IPs = lists:foldl(fun extract_ip_addresses/2, [], TLVs),
    IPs.
    

%%--------------------------------------------------------------------
%% @private
%% @doc
%%
%% From the list of transit nodes, rooted on ourselves, we need to
%% find the true 'nexthop' node. Take into account the 'next' node may
%% be a pseudo-node and that we may not see a true 'nexthop' if there
%% are lsp issues.
%%
%% @end
%%--------------------------------------------------------------------
get_nexthop(Nodes) when length(Nodes) >= 2 ->
    <<Candidate:6/binary, PN:8>> = lists:nth(2, Nodes),
    case PN of
	0 -> Candidate;
	_ -> 
	    case length(Nodes) >= 3 of
		true -> <<Candidate2:6/binary, _:8>> = lists:nth(3, Nodes),
			Candidate2;
		_ -> unreachable
	    end
    end;
get_nexthop(Nodes) ->
    io:format("Node list length was ~b!~n", [length(Nodes)]),
    unreachable.

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

populate_links(DB) ->
    Now = isis_protocol:current_timestamp(),
    F = ets:fun2ms(fun(#isis_lsp{lsp_id = LSP_Id, remaining_lifetime = L,
				 last_update = U, sequence_number = N, tlv = TLV})
			 when (L - (Now - U)) >= 0 ->
			   {LSP_Id, TLV}
		   end),
    ValidLSPs = ets:select(DB, F),
    Reachability =
	fun({LSP_Id, TLV}, Acc) ->
		<<Sys:7/binary, _/binary>> = LSP_Id,
		extract_reachability(Acc, Sys, TLV)
	end,
    Edges = lists:foldl(Reachability, dict:new(), ValidLSPs),
    Edges.

extract_ip_addresses(#isis_tlv_ip_internal_reachability{ip_reachability = R}, Ts) ->
    lists:map(fun(#isis_tlv_ip_internal_reachability_detail{ip_address = A, subnet_mask = M,
							    default = #isis_metric_information{
									 metric = Metric
									}}) ->
		      %% MAP Subnet mask to a len here!
		      {#isis_address{afi = ipv4, address = A, mask = M, metric = Metric}, undefined}
	      end, R)
	++ Ts;
extract_ip_addresses(#isis_tlv_extended_ip_reachability{reachability = R}, Ts) ->
    lists:map(fun(#isis_tlv_extended_ip_reachability_detail{prefix = P, mask_len = M, metric = Metric}) ->
		      {#isis_address{afi = ipv4, address = P, mask = M, metric = Metric}, undefined}
	      end, R)
	++ Ts;
extract_ip_addresses(#isis_tlv_ipv6_reachability{reachability = R}, Ts) ->
    lists:map(fun(#isis_tlv_ipv6_reachability_detail{prefix = P, mask_len = M,
						     metric = Metric, sub_tlv = SubTLVs}) ->
		      Source = extract_source(SubTLVs, ipv6),
		      {#isis_address{afi = ipv6, address = P, mask = M, metric = Metric}, Source}
	      end, R)
	++ Ts.

extract_source(SubTLVs, Afi) ->
    S = lists:filtermap(
	  fun(#isis_subtlv_srcdst{prefix_length = PL, prefix = P}) ->
		  {true, #isis_address{afi = Afi, address = P, mask = PL}};
	     (_) ->
		  false
	  end, SubTLVs),
    case length(S) of
	0 -> undefined;
	_ ->
	    %% Just take the first...
	    lists:nth(1, S)
    end.
