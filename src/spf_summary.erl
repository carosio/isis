%%%-------------------------------------------------------------------
%%% @author Rick Payne <rickp@rossfell.co.uk>
%%% @copyright (C) 2014, Alistair Woodman, California USA <awoodman@netdef.org>
%%% @doc
%%%
%%% Subscription engine for distributing the results of an SPF run to
%%% the various subscribers (RIB feed, web feed etc)
%%%
%%% @end
%%% Created : 31 Mar 2014 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------
-module(spf_summary).

-behaviour(gen_server).

%% API
-export([start_link/0,
	 subscribe/1, unsubscribe/1,
	 notify_subscribers/1,
	 last_run/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE).

-record(state, {
	  subscribers,
	  last_run_level_1 = undef,
	  last_run_level_2 = undef
	 }).

%%%===================================================================
%%% API
%%%===================================================================
subscribe(Pid) ->
    gen_server:call(?MODULE, {subscribe, Pid}).

unsubscribe(Pid) ->
    gen_server:call(?MODULE, {unsubscribe, Pid}).

notify_subscribers(Summary) ->
    gen_server:call(?MODULE, {notify, Summary}).

last_run(Level) ->
    gen_server:call(?MODULE, {last_run, Level}).

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

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
    process_flag(trap_exit, true),
    {ok, #state{subscribers = dict:new()}}.

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
handle_call({subscribe, Pid}, _From, #state{subscribers = Subscribers,
					    last_run_level_1 = LR} = State) ->
    %% Monitor the subscribing process, so we know if they die
    erlang:monitor(process, Pid),
    NewDict = dict:store(Pid, [], Subscribers),
    case LR of
	undef -> ok;
	M -> Pid ! {spf_summary, M}
    end,
    {reply, ok, State#state{subscribers = NewDict}};

handle_call({unsubscribe, Pid}, _From, State) ->
    NewState = remove_subscriber(Pid, State),
    {reply, ok, NewState};

handle_call({notify, Summary}, _From, #state{subscribers = Subscribers} = State) ->
    notify_subscribers(Summary, Subscribers),
    {reply, ok, State};

handle_call({last_run, level_1}, _From, #state{last_run_level_1 = LR} = State) ->
    {reply, LR, State};
handle_call({last_run, level_2}, _From, #state{last_run_level_2 = LR} = State) ->
    {reply, LR, State};
handle_call({last_run, _}, _From, State) ->
    {reply, not_run, State};


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
handle_cast({last_run, {_, level_1, _, _} = Message}, State) ->
    {noreply, State#state{last_run_level_1 = Message}};
handle_cast({last_run, {_, level_2, _, _} = Message}, State) ->
    {noreply, State#state{last_run_level_2 = Message}};

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
remove_subscriber(Pid, #state{subscribers = Subscribers} = State) ->
    NewSubscribers =
	case dict:find(Pid, Subscribers) of
	    {ok, _Value} ->
		dict:erase(Pid, Subscribers);
	    error ->Subscribers
	end,
    State#state{subscribers = NewSubscribers}.

notify_subscribers(Message, Subscribers) ->
    Pids = dict:fetch_keys(Subscribers),
    lists:foreach(
      fun(Pid) ->
	      Pid ! {spf_summary, Message} end, Pids),
    gen_server:cast(?MODULE, {last_run, Message}),
    ok.
