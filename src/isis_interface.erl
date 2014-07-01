%%%-------------------------------------------------------------------
%%% @author Rick Payne <rickp@rossfell.co.uk>
%%% @copyright (C) 2014, Alistair Woodman, California USA <awoodman@netdef.org>
%%% @doc
%%%
%%% @end
%%% Created : 18 Jan 2014 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------
-module(isis_interface).

-behaviour(gen_server).

-include("isis_system.hrl").
-include("isis_protocol.hrl").

-define(SIOCGIFMTU, 16#8921).
-define(SIOCGIFHWADDR, 16#8927).
-define(SIOCADDMULTI, 16#8931).
-define(SIOCGIFINDEX, 16#8933).

%% API
-export([start_link/1, send_pdu/5, stop/1,
	 get_state/3, get_state/1, set/2,
	 enable_level/2, disable_level/2, levels/1, get_level_pid/2,
	 get_addresses/2,
	 clear_neighbors/1,
	 dump_config/1]).

%% Debug export
-export([]).
-compile(export_all).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE).
-define(ETH_P_802_2, 16#0400).

-record(state, {
	  name,            %% Interface name
	  ifindex,         %% Interface ifindex
	  socket,          %% Procket socket...
	  port,            %% Erlang port handling socket
	  mac,             %% This interface's MAC address
	  mtu,             %% Interface MTU
	  circuit_type,    %% Level-1 or level-1-2 (just level-2 is invalid)
	  level1,          %% Pid handling the levels
	  level2
	 }).

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
send_pdu(Pid, Type, Packet, Packet_Size, Level) ->
    gen_server:cast(Pid, {send_pdu, Type, Packet, Packet_Size, Level}).

stop(Pid) ->
    gen_server:cast(Pid, stop).

get_state(Pid, Level, Item) ->
    gen_server:call(Pid, {get_state, Level, Item}).

get_state(Pid) ->
    gen_server:call(Pid, {get_state}).

set(Pid, Values) ->
    gen_server:call(Pid, {set, Values}).

get_level_pid(Pid, Level) ->
    gen_server:call(Pid, {get_level_pid, Level}).

get_level(Pid, Level, Value) ->
    gen_server:call(Pid, {get, Level, Value}).

enable_level(Pid, Level) ->
    gen_server:call(Pid, {enable, Level}).

disable_level(Pid, Level) ->
    gen_server:call(Pid, {disable, Level}).

levels(Pid) ->
    gen_server:call(Pid, {levels}).

get_addresses(Pid, Family) ->
    gen_server:call(Pid, {get_addresses, Family}).

clear_neighbors(Pid) ->
    gen_server:cast(Pid, {clear_neighbors}).

dump_config(Pid) ->
    gen_server:call(Pid, {dump_config}).

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
    State = extract_args(Args, #state{}),
    {Socket, Mac, Ifindex, MTU, Port} = create_port(State#state.name),
    StartState = State#state{socket = Socket, port = Port,
			     mac = Mac, mtu = MTU,
			     ifindex = Ifindex,
			     level1 = undef,
			     level2 = undef
			    },
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
handle_call({get_state, _, mac}, _From, State) ->
    {reply, State#state.mac, State};
handle_call({get_state, _, mtu}, _From, State) ->
    {reply, State#state.mtu, State};
handle_call({get_state, _, ifindex}, _From, State) ->
    {reply, State#state.ifindex, State};
handle_call({get_state, level_1, Item}, _From,
	    #state{level1 = L1Pid} = State) when is_pid(L1Pid) ->
    {reply, isis_interface_level:get_state(L1Pid, Item), State};
handle_call({get_state, level_2, Item}, _From,
	    #state{level2 = L2Pid} = State) when is_pid(L2Pid) ->
    {reply, isis_interface_level:get_state(L2Pid, Item), State};
handle_call({get_state, _, _}, _From, State) ->
    {reply, level_not_configured, State};

handle_call({get_state}, _From, State) ->
    {reply, State, State};

handle_call({set, Values}, _From, State) ->
    NewState = set_values(Values, State),
    {reply, ok, NewState};

handle_call({enable, Level}, _From, State) ->
    io:format("Enabling level ~p~n", [Level]),
    handle_enable_level(Level, State);
handle_call({disable, Level}, _From, State) ->
    handle_disable_level(Level, State);

handle_call({levels}, _From, State) ->
    Levels = 
	case {State#state.level1, State#state.level2} of
	    {undef, undef} -> [];
	    {_, undef} -> [level_2];
	    {undef, _} -> [level_1];
	    {_, _} -> [level_1, level_2]
	end,
    {reply, Levels, State};

handle_call({get_level_pid, level_1}, _From,
	    #state{level1 = L1Pid} = State) when is_pid(L1Pid) ->
    {reply, L1Pid, State};
handle_call({get_level_pid, level_2}, _From,
	    #state{level2 = L2Pid} = State) when is_pid(L2Pid) ->
    {reply, L2Pid, State};
handle_call({get_level_pid, _}, _From, State) ->
    {reply, not_enabled, State};

handle_call({get_addresses, Family}, _From, State) ->
    Interface = isis_system:get_interface(State#state.name),
    Matcher = fun(#isis_address{afi = F, address = A})
		    when F =:= Family -> {true, A};
		 (_) -> false
	      end,
    Addresses = lists:filtermap(Matcher,
				Interface#isis_interface.addresses),
    {reply, Addresses, State};

handle_call({dump_config}, _From, State) ->
    dump_config_state(State),
    {reply, ok, State};

handle_call({get, level_1, Value}, _From, State) ->
    R = isis_interface_level:get_state(State#state.level1, Value),
    {reply, R, State};
handle_call({get, level_2, Value}, _From, State) ->
    R = isis_interface_level:get_state(State#state.level2, Value),
    {reply, R, State};

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
handle_cast({send_pdu, iih, PDU, PDU_Size, Level}, State) ->
    send_packet(PDU, PDU_Size, Level, State),
    {noreply, State};
handle_cast({send_pdu, _Type, PDU, PDU_Size, level_1},
	    #state{level1 = P} = State) when is_pid(P) ->
    Adj = isis_interface_level:get_state(P, up_adjacencies),
    case length(dict:fetch_keys(Adj)) of
	0 -> no_adj;
	_ -> send_packet(PDU, PDU_Size, level_1, State)
    end,
    {noreply, State};
handle_cast({send_pdu, _Type, PDU, PDU_Size, level_2},
	    #state{level2 = P} = State) when is_pid(P) ->
    Adj = isis_interface_level:get_state(P, up_adjacencies),
    case length(dict:fetch_keys(Adj)) of
	0 -> no_adj;
	_ -> send_packet(PDU, PDU_Size, level_2, State)
    end,
    {noreply, State};
handle_cast({send_pdu, _PDU, _PDU_Size, _}, State) ->
    {noreply, State};

handle_cast(stop, #state{port = Port,
			 level1 = Level1,
			 level2 = Level2} = State) ->
    %% Close down the port (does this close the socket?)
    erlang:port_close(Port),
    %% Notify our adjacencies
    case is_pid(Level1) of
	true -> gen_server:cast(Level1, stop);
	_ -> no_process
    end,
    case is_pid(Level2) of
	true -> gen_server:cast(Level2, stop);
	_ -> no_process
    end,
    {stop, normal, State};

handle_cast({set, level_1, Values}, #state{level1 = P} = State)
  when is_pid(P) ->
    isis_interface_level:set(P, Values),
    {noreply, State};
handle_cast({set, level_2, Values}, #state{level2 = P} = State)
  when is_pid(P) ->
    isis_interface_level:set(P, Values),
    {noreply,  State};
handle_cast({set, _, _}, State) ->
    {noreply, State};

handle_cast({clear_neighbors}, #state{
				 level1 = Level1,
				 level2 = Level2} = State) ->
    case is_pid(Level1) of
	true -> isis_interface_level:clear_neighbors(Level1);
	_ -> no_level
    end,
    case is_pid(Level2) of
	true -> isis_interface_level:clear_neighbors(Level2);
	_ -> no_level
    end,
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
handle_info({_port, {data,
		     <<_To:6/binary, From:6/binary, _Len:16,
		       16#FE:8, 16#FE:8, 3:8, PDU/binary>>}},
	    State) ->
    NewState = 
	case isis_protocol:decode(PDU) of
	    {ok, DecodedPDU} ->
		handle_pdu(From, DecodedPDU, State),
		State;
	    _ ->
		%% io:format("Failed to decode: ~p~n", [PDU]),
		State
	end,
    {noreply, NewState};

handle_info({_port, {data, _}}, State) ->
    {noreply, State};


handle_info(Info, State) ->
    io:format("Unknown message: ~p", [Info]),
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
%% Handle the various PDUs that we can receive on this interface
%%
%% @end
%%--------------------------------------------------------------------
handle_pdu(From, #isis_iih{pdu_type = level1_iih} = PDU, #state{level1 = Pid} = State)
  when is_pid(Pid) ->
    isis_interface_level:handle_pdu(Pid, From, PDU);
handle_pdu(From, #isis_iih{pdu_type = level2_iih} = PDU, #state{level2 = Pid} = State)
  when is_pid(Pid) ->
    isis_interface_level:handle_pdu(Pid, From, PDU);
handle_pdu(From, #isis_lsp{pdu_type = level1_lsp} = PDU, #state{level1 = Pid} = State)
  when is_pid(Pid) ->
    isis_interface_level:handle_pdu(Pid, From, PDU);
handle_pdu(From, #isis_lsp{pdu_type = level2_lsp} = PDU, #state{level2 = Pid} = State)
  when is_pid(Pid) ->
    isis_interface_level:handle_pdu(Pid, From, PDU);
handle_pdu(From, #isis_csnp{pdu_type = level1_csnp} = PDU, #state{level1 = Pid} = State)
  when is_pid(Pid) ->
    isis_interface_level:handle_pdu(Pid, From, PDU);
handle_pdu(From, #isis_csnp{pdu_type = level2_csnp} = PDU, #state{level2 = Pid} = State)
  when is_pid(Pid) ->
    isis_interface_level:handle_pdu(Pid, From, PDU);
handle_pdu(From, #isis_psnp{pdu_type = level1_psnp} = PDU, #state{level1 = Pid} = State)
  when is_pid(Pid) ->
    isis_interface_level:handle_pdu(Pid, From, PDU);
handle_pdu(From, #isis_psnp{pdu_type = level2_psnp} = PDU, #state{level2 = Pid} = State)
  when is_pid(Pid) ->
    isis_interface_level:handle_pdu(Pid, From, PDU);
handle_pdu(_From, _Pdu, State) ->
    State.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% 
%% Turn on a level
%%
%% @end
%%--------------------------------------------------------------------
handle_enable_level(level_1, #state{level1 = Level_1} = State) ->
    Level = 
	case Level_1 of
	    undef ->
		{ok, Pid} = isis_interface_level:start_link([{level, level_1},
							     {snpa, State#state.mac},
							     {interface, State#state.name, self(),
							      State#state.mtu}]),
		Pid;
	    _ -> Level_1
	end,
    {reply, ok, State#state{level1 = Level}};
handle_enable_level(level_2, #state{level2 = Level_2} = State) ->
    Level = 
	case Level_2 of
	    undef ->
		{ok, Pid} = isis_interface_level:start_link([{level, level_2},
							     {snpa, State#state.mac},
							     {interface, State#state.name, self()}]),
		Pid;
	    _ -> Level_2
	end,
    {reply, ok, State#state{level2 = Level}};
handle_enable_level(_, State) ->
    {reply, invalid_level, State}.

handle_disable_level(level_1, #state{level1 = Level_1} = State) when is_pid(Level_1) ->
    isis_interface_level:stop(Level_1),
    {reply, ok, State#state{level1 = undef}};
handle_disable_level(level_2, #state{level2 = Level_2} = State) when is_pid(Level_2) ->
    isis_interface_level:stop(Level_2),
    {reply, ok, State#state{level2 = undef}};
handle_disable_level(_, State) ->
    {reply, invalid_level, State}.


%%--------------------------------------------------------------------
%% @private
%% @doc
%% 
%%
%%
%% @end
%%--------------------------------------------------------------------
-spec set_values(list(), tuple()) -> tuple().
set_values([{mtu, Value} | T], State) when is_integer(Value) ->
    set_values(T, State#state{mtu = Value});
set_values([{mac, Binary} | T], State) ->
    set_values(T, State#state{mac = Binary});
set_values([], State) ->
    State.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% 
%%
%%
%% @end
%%--------------------------------------------------------------------

-spec create_port(string()) -> {integer(), binary(), integer(), integer(), port()} | error.
create_port(Name) ->
    {ok, S} = procket:open(0,
			   [{progname, "sudo /usr/local/bin/procket"},
			    {family, packet},
			    {type, raw},
			    {protocol, ?ETH_P_802_2},
			    {interface, Name},
			    {isis}]),
    {Ifindex, Mac, MTU} = interface_details(S, Name),
    LL = create_sockaddr_ll(Ifindex),
    ok = procket:bind(S, LL),
    Port = erlang:open_port({fd, S, S}, [binary, stream]),
    {S, Mac, Ifindex, MTU, Port}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% 
%%
%%
%% @end
%%--------------------------------------------------------------------
send_packet(Pdu, Pdu_Size, Level, State) ->
    Destination =
	case Level of 
	    level_1 -> <<1, 16#80, 16#C2, 0, 0, 16#14>>;
	    level_2 -> <<1, 16#80, 16#C2, 0, 0, 16#15>>
	end,
    Source = State#state.mac,
    Header = <<Destination/binary, Source/binary>>, 
    Len = Pdu_Size + 3,
    Packet = list_to_binary([Header, <<Len:16, 16#FE, 16#FE, 16#03>> | Pdu]),
    LL = create_sockaddr_ll(State#state.ifindex),
    Result = procket:sendto(State#state.socket, Packet, 0, LL),
    Result.



%%--------------------------------------------------------------------
%% @private
%% @doc
%% 
%%
%%
%% @end
%%--------------------------------------------------------------------
-spec create_sockaddr_ll(integer()) -> binary().
create_sockaddr_ll(Ifindex) ->
    Family = procket:family(packet),
    <<Family:16/native, ?ETH_P_802_2:16/native, Ifindex:32/native,
      0:16, 0:8, 0:8, 0:8/unit:8>>.

%%
%% Linux specific, be nice to get this in the
%% procket module...
%%
interface_details(Socket, Name) ->
    N = list_to_binary(Name),
    Req = <<N/binary, 0:(8*(40 - byte_size(N)))>>,
    case procket:ioctl(Socket, ?SIOCGIFHWADDR, Req) of
	{error, _} -> error;
	{ok, Mac_Response} -> 
	    {ok, Ifindex_Response} = procket:ioctl(Socket,
						   ?SIOCGIFINDEX, Req),
	    {ok, MTU_Response} = procket:ioctl(Socket,
					       ?SIOCGIFMTU, Req),
	    <<_:16/binary, I:32/native, _/binary>> = Ifindex_Response,
	    <<_:18/binary, Mac:6/binary, _/binary>> = Mac_Response,
	    <<_:16/binary, MTU:16/native, _/binary>> = MTU_Response,
	    %% Req2 = <<N/binary, 0:(8*(16 - byte_size(N))), I:16/native,
	    %%   	     16#01, 16#80, 16#c2, 0, 0, 16#14, 0:128>>,
	    %% Req3 = <<N/binary, 0:(8*(16 - byte_size(N))), I:16/native,
	    %% 	     16#01, 16#80, 16#c2, 0, 0, 16#15, 0:128>>,
	    %% {ok, _} = procket:ioctl(Socket, ?SIOCADDMULTI, Req2),
	    %% {ok, _} = procket:ioctl(Socket, ?SIOCADDMULTI, Req3),
	    {I, Mac, MTU}
    end.


extract_args([{name, Name} | T], State) ->
    extract_args(T, State#state{name = Name});
extract_args([{circuit_type, Type} | T] , State) ->
    extract_args(T, State#state{circuit_type = Type});
extract_args([], State) ->
    State.

dump_config_fields([{level1, P} | Fs], #state{name = N} = State)
  when is_pid(P) ->
    io:format("isis_system:enable_level(\"~s\", level_1).~n", [N]),
    isis_interface_level:dump_config(N, level_1, P),
    dump_config_fields(Fs, State);
dump_config_fields([{level2, P} | Fs], #state{name = N} = State)
  when is_pid(P) ->
    io:format("isis_system:enable_level(\"~s\", level_2).~n", [N]),
    isis_interface_level:dump_config(N, level_2, P),
    dump_config_fields(Fs, State);
dump_config_fields([_ | Fs], State) ->
    dump_config_fields(Fs, State);
dump_config_fields([], _) ->
    ok.

dump_config_state(State) ->
    S = lists:zip(record_info(fields, state),
		  tl(erlang:tuple_to_list(State))),
    dump_config_fields(S, State).
