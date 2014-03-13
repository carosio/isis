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
	 add_interface/1, del_interface/1, list_interfaces/0, set_interface/2,
	 enable_level/2, disable_level/2,
	 set_hostname/1,
	 areas/0, lsps/0,
	 system_id/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE).

-record(state, {system_id,
		areas = [],
		lsps = [],
		interfaces,   %% Our 'state' per interface
		pseudonodes,
		refresh_timer}).

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

enable_level(Interface, Level) ->
    gen_server:call(?MODULE, {enable_level, Interface, Level}).

disable_level(Interface, Level) ->
    gen_server:call(?MODULE, {disable_level, Interface, Level}).

system_id() ->
    gen_server:call(?MODULE, {system_id}).

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
    State = #state{interfaces = dict:new(),
		   pseudonodes = dict:new()},
    StartState = extract_args(Args, State),
    SysID = StartState#state.system_id,
    LSP_Id = <<SysID/binary, 0:16>>,
    Lsp = #isis_lsp{lsp_id = LSP_Id, remaining_lifetime = 1200,
		    last_update = isis_protocol:current_timestamp(),
		    sequence_number = 1, partition = false,
		    overload = false, isis_type = level_1_2,
		    pdu_type = level1_lsp,
		    tlv = [#isis_tlv_area_address{areas = StartState#state.areas},
			   #isis_tlv_protocols_supported{protocols = [ipv4, ipv6]},
			   #isis_tlv_extended_reachability{reachability = []}
			  ]},
    CSum = isis_protocol:checksum(Lsp),
    L1Lsp = Lsp#isis_lsp{pdu_type = level1_lsp, checksum = CSum},
    L2Lsp = Lsp#isis_lsp{pdu_type = level2_lsp, checksum = CSum},
    isis_lspdb:store_lsp(level_1, L1Lsp),
    isis_lspdb:store_lsp(level_2, L2Lsp),
    zclient:subscribe(self()),
    Timer = erlang:start_timer(600 * 1000, self(), refreshtimer),
    {ok, StartState#state{lsps = [LSP_Id], refresh_timer = Timer}}.

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
    NextState = 
	case is_pid(Interface#isis_interface.pid) of
	    true -> State;
	    _ -> {ok, InterfacePid} = isis_interface:start_link([{name, Name}]),
		 erlang:monitor(process, InterfacePid),
		 NewInterfaces = dict:store(Name,
					    Interface#isis_interface{pid = InterfacePid,
								     enabled = true},
					    Interfaces),
		 State#state{interfaces = NewInterfaces}
	end,
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
    case dict:find(InterfaceName, Interfaces) of
	{ok, Interface} ->
	    case is_pid(Interface#isis_interface.pid) of
		true -> {reply,
			 isis_interface:enable_level(Interface#isis_interface.pid, Level),
			 State};
		_ -> {reply, not_enabled, State}
	    end;
	Buh ->
	    io:format("Got: ~p~n", [Buh]),
	    {reply, not_found, State}
    end;

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

handle_call({system_id}, _From,
	    #state{system_id = ID} = State) ->
    {reply, ID, State};

handle_call({areas}, _From, #state{areas = Areas} = State) ->
    {reply, Areas, State};

handle_call({lsps}, _From, #state{lsps = LSPs} = State) ->
    {reply, LSPs, State};

handle_call({hostname, Name}, _From, #state{lsps = LSPs} = State) ->
    lists:map(fun(LSP) ->
		      isis_lspdb:replace_tlv(level_1, #isis_tlv_dynamic_hostname{hostname = Name}, LSP),
		      isis_lspdb:replace_tlv(level_2, #isis_tlv_dynamic_hostname{hostname = Name}, LSP)
	      end, LSPs),
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
handle_info({timeout, _Ref, refreshtimer}, State) ->
    refresh_lsps(level_1, State),
    refresh_lsps(level_2, State),
    Timer = erlang:start_timer(600 * 1000, self(), refreshtimer),
    {noreply, State#state{refresh_timer = Timer}};
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

%%%===================================================================
%%% Refresh LSPs
%%%===================================================================
refresh_lsps(Level, State) ->
    LSPs = isis_lspdb:lookup_lsps(State#state.lsps, isis_lspdb:get_db(Level)),
    Refresher =
	fun(L) ->
		NewLSP = L#isis_lsp{sequence_number = (L#isis_lsp.sequence_number+1),
				    remaining_lifetime = 1200,
				    last_update = isis_protocol:current_timestamp()},
		isis_lspdb:store_lsp(Level, NewLSP),
		isis_lspdb:flood_lsp(Level, NewLSP)
	end,
    lists:map(Refresher, LSPs).

%%%===================================================================
%%% Add interface
%%%===================================================================
add_interface(#zclient_interface{
		 name = Name, ifindex = Ifindex,
		 mtu = MTU, mtu6 = MTU6, mac = Mac}, State) ->
    I = 
	case dict:is_key(Name, State#state.interfaces) of
	    true -> dict:fetch(Name, State#state.interfaces);
	    _ -> #isis_interface{name = Name}
	end,
    NewInterfaces = 
	dict:store(Name, I#isis_interface{ifindex = Ifindex,
					  mac = Mac, mtu = MTU, mtu6 = MTU6},
		   State#state.interfaces),
    State#state{interfaces = NewInterfaces}.

add_address(#zclient_address{afi = AFI, address = Address,
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
	     
