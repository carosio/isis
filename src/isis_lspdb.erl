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

-include("isis_protocol.hrl").
-include_lib("stdlib/include/ms_transform.hrl").

%% API
-export([start_link/1, get_db/1,
	 lookup_lsps/2, store_lsp/2, delete_lsp/2,
	 summary/1, range/3]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE).

-record(state, {db,
	        expiry_timer}).

%%%===================================================================
%%% API
%%%===================================================================
%%--------------------------------------------------------------------
%% @doc
%%
%% Store an LSP into the database.
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
summary(DB) ->
    lsp_summary(DB).

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
init([]) ->
    DB = ets:new(lspdb, [ordered_set, {keypos, #isis_lsp.lsp_id}]),
    Timer = start_timer(),
    {ok, #state{db = DB, expiry_timer = Timer}}.

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
    {reply, ets:insert(State#state.db, LSP), State};

handle_call({delete, LSP},
	    _From, State) ->
    {reply, ets:delete(State#state.db, LSP), State};

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
handle_info({timeout, _Ref, expire}, State) ->
    erlang:cancel_timer(State#state.expiry_timer),
    expire_lsps(State),
    Timer = start_timer(),
    {noreply, State#state{expiry_timer = Timer}};
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
-spec lookup([binary()], integer()) -> [isis_lsp()].
lookup(IDs, DB) ->
    lists:filtermap(fun(LSP) ->
		      case ets:lookup(DB, LSP) of
			  [L] -> {true, isis_protocol:fixup_lifetime(L)};
			  [] -> false
		      end
	      end, IDs).

%%--------------------------------------------------------------------
%% @private
%% @doc
%%
%% Summarise the database (for CSNP generation). Returned format is:
%% {Key, Sequence Number, Checksum, Remaining Lifetime}
%%
%% @end
%%--------------------------------------------------------------------
-spec lsp_summary(integer()) -> [{binary(), integer(), integer(), integer()}].
lsp_summary(DB) ->
    Now = isis_protocol:current_timestamp(),
    F = ets:fun2ms(fun(#isis_lsp{lsp_id = LSP_Id, remaining_lifetime = L,
				 sequence_number = N,
				 last_update = U, checksum = C}) ->
			   {LSP_Id, N, C, L - (Now - U)} end),
    ets:select(DB, F).

%%--------------------------------------------------------------------
%% @private
%% @doc
%%
%% Summarise a range of the database. Format returned is:
%% {LSP ID, Sequence Number, Checksum, Remaining Lifetime}
%%
%% @end
%%--------------------------------------------------------------------
-spec lsp_range(binary(), binary(), integer()) ->
		       [{binary(), integer(), integer(), integer()}].
lsp_range(Start_ID, End_ID, DB) ->
    Now = isis_protocol:current_timestamp(),
    F = ets:fun2ms(fun(#isis_lsp{lsp_id = LSP_Id, remaining_lifetime = L,
				 last_update = U, sequence_number = N, checksum = C})
		      when LSP_Id >= Start_ID, LSP_Id =< End_ID, (L - (Now - U)) > 0 ->
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
-spec expire_lsps(tuple()) -> tuple().
expire_lsps(#state{db = DB}) ->
    Now = isis_protocol:current_timestamp(),
    F = ets:fun2ms(fun(#isis_lsp{lsp_id = LSP_Id, remaining_lifetime = L,
				 last_update = U, sequence_number = N, checksum = C})
		      when (L - (Now - U)) < -?DEFAULT_LSP_AGEOUT ->
			   true end),
    ets:select_delete(DB, F).


start_timer() ->
    erlang:start_timer((?DEFAULT_EXPIRY_TIMER * 1000), self(), expire).
