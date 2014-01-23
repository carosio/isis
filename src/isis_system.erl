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
-export([start_link/1, add_interface/2, del_interface/2, list_interfaces/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE).

-record(state, {system_id,
		interfaces}).

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

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Add an interface to this IS-IS system, which will spawn a process
%% to send hello's, handle incoming and outgoing packets etc..
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------

add_interface(Ref, Ifindex) ->
    gen_server:call(Ref, {add_interface, Ifindex, Ref}).

del_interface(Ref, Ifindex) ->
    gen_server:call(Ref, {del_interface, Ifindex}).

list_interfaces(Ref) ->
    gen_server:call(Ref, {list_interfaces}).

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
    State = #state{interfaces = dict:new()},
    io:format("~p~n", [Args]),
    State = extract_args(Args, State),
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
handle_call({add_interface, Name, Ref}, _From,
	    #state{interfaces = Interfaces} = State) ->
    {ok, InterfacePid} = isis_interface:start_link([{Name, Ref}]),
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

handle_call({list_interfaces}, _From,
	    #state{interfaces = Interfaces} = State) ->
    Reply = Interfaces,
    {reply, Reply, State};

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
extract_arg({system_id, Id}, State) ->
    State#state{system_id = Id};
extract_arg(_, State) ->
    State.

extract_args([H | T], State) ->
    extract_args(T, extract_arg(H, State));
extract_args([], State) ->
    State.
