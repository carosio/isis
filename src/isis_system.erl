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

%% API
-export([start_link/1,
	 add_interface/2, del_interface/2, list_interfaces/1, set_interface/3,
	 enable_level/3, disable_level/3,
	 areas/1,
	 system_id/1, lspdb/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE).

-record(state, {system_id,
		areas = [],
		level1_lspdb,
		level2_lspdb,
		interfaces,
		pseudonodes}).

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

%%--------------------------------------------------------------------
%% @doc
%%
%% Add an interface to this IS-IS system, which will spawn a process
%% to send hello's, handle incoming and outgoing packets etc..
%%
%% @end
%%--------------------------------------------------------------------
-spec add_interface(pid(), string()) -> ok | error.
add_interface(Ref, Name) ->
    gen_server:call(Ref, {add_interface, Name, Ref}).

-spec del_interface(pid(), string()) -> ok | error.
del_interface(Ref, Name) ->
    gen_server:call(Ref, {del_interface, Name}).

set_interface(Ref, Name, Values) ->
    gen_server:call(Ref, {set_interface, Name, Values}).

list_interfaces(Ref) ->
    gen_server:call(Ref, {list_interfaces}).

enable_level(Ref, Interface, Level) ->
    gen_server:call(Ref, {enable_level, Interface, Level}).

disable_level(Ref, Interface, Level) ->
    gen_server:call(Ref, {disable_level, Interface, Level}).

system_id(Ref) ->
    gen_server:call(Ref, {system_id}).

areas(Ref) ->
    gen_server:call(Ref, {areas}).

-spec lspdb(pid(), atom()) -> pid() | atom().
lspdb(Ref, Level) ->
    gen_server:call(Ref, {lspdb, Level}).

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
    {ok, Level1_LSPDb} = isis_lspdb:start_link([{table, level_1}]),
    erlang:monitor(process, Level1_LSPDb),
    {ok, Level2_LSPDb} = isis_lspdb:start_link([{table, level_2}]),
    erlang:monitor(process, Level2_LSPDb),
    State = #state{interfaces = dict:new(),
		   pseudonodes = dict:new(),
		   level1_lspdb = Level1_LSPDb,
		   level2_lspdb = Level2_LSPDb},
    StartState = extract_args(Args, State),
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
handle_call({add_interface, _, _}, _From,
	    #state{system_id = ID} = State) when is_binary(ID) == false ->
    {reply, {error, "invalid system id"}, State};
handle_call({add_interface, Name, Ref}, _From,
	    #state{interfaces = Interfaces} = State) ->
    {ok, InterfacePid} = isis_interface:start_link([{name, Name},
						    {system_ref, Ref}]),
    erlang:monitor(process, InterfacePid),
    NewInterfaces = dict:store(Name, InterfacePid, Interfaces),
    {reply, ok, State#state{interfaces = NewInterfaces}};

handle_call({del_interface, Name}, _From,
	    #state{interfaces = Interfaces} = State) ->
    NewInterfaces =
	case dict:find(Name, Interfaces) of
	    {ok, Pid} ->
		isis_interface:stop(Pid),
		dict:erase(Name, Interfaces);
	    _ ->
		Interfaces
	end,
    {reply, ok, State#state{interfaces = NewInterfaces}};

handle_call({enable_level, Interface, Level}, _From,
	    #state{interfaces = Interfaces} = State) ->
    case dict:find(Interface, Interfaces) of
	{ok, Pid} ->
	    R = isis_interface:enable_level(Pid, Level),
	    {reply, R, State};
	_ ->
	    {reply, interface_not_found, State}
    end;

handle_call({disable_level, Interface, Level}, _From,
	    #state{interfaces = Interfaces} = State) ->
    case dict:find(Interface, Interfaces) of
	{ok, Pid} ->
	    R = isis_interface:disable_level(Pid, Level),
	    {reply, R, State};
	_ ->
	    {reply, interface_not_found, State}
    end;

handle_call({set_interface, Name, Values}, _From,
	    #state{interfaces = Interfaces} = State) ->
    case dict:find(Name, Interfaces) of
	{ok, Pid} ->
	    isis_interface:set(Pid, Values);
	_ -> ok
    end,
    {reply, ok, State};

handle_call({list_interfaces}, _From,
	    #state{interfaces = Interfaces} = State) ->
    Reply = Interfaces,
    {reply, Reply, State};

handle_call({system_id}, _From,
	    #state{system_id = ID} = State) ->
    {reply, ID, State};

handle_call({areas}, _From, #state{areas = Areas} = State) ->
    {reply, Areas, State};

handle_call({lspdb, level_1}, _From,
	    #state{level1_lspdb = ID} = State) ->
    {reply, ID, State};
handle_call({lspdb, level_2}, _From,
	    #state{level2_lspdb = ID} = State) ->
    {reply, ID, State};
handle_call({lspdb, _}, _From, State) ->
    {reply, invalid_database, State};

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
extract_args([{system_id, Id} | T], State) ->
    extract_args(T, State#state{system_id = Id});
extract_args([{areas, Areas} | T], State) ->
    extract_args(T, State#state{areas = Areas});
extract_args([_ | T], State) ->
    extract_args(T, State);
extract_args([], State) ->
    State.
