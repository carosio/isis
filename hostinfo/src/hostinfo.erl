%%%-------------------------------------------------------------------
%%% @author Rick Payne <rickp@rossfell.co.uk>
%%% @copyright (C) 2014, Alistair Woodman, California USA <awoodman@netdef.org>
%%% @doc
%%%
%%% This file is part of AutoISIS.
%%%
%%% License:
%%% This code is licensed to you under the Apache License, Version 2.0
%%% (the "License"); you may not use this file except in compliance with
%%% the License. You may obtain a copy of the License at
%%% 
%%%   http://www.apache.org/licenses/LICENSE-2.0
%%% 
%%% Unless required by applicable law or agreed to in writing,
%%% software distributed under the License is distributed on an
%%% "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
%%% KIND, either express or implied.  See the License for the
%%% specific language governing permissions and limitations
%%% under the License.
%%%
%%% @end
%%% Created : 6 Dec 2014 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------
-module(hostinfo).
-behaviour(gen_server).

-include("hostinfo.hrl").
-include("../../src/isis_protocol.hrl").
-include("../../src/isis_geninfo.hrl").

%% API
-export([start_link/0, get_state/0,
	 subscribe/0, unsubscribe/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE).

-record(state, {
	  hosts,          %% Host -> TLVs mapping
	  clients,        %% Websocket subscribers
	  refresh_timer,
	  tlvs = [],
	  dnssd_tlvs = []
	 }).

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
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).


%%%===================================================================
%%% gen_server callbacks
%%%===================================================================
get_state() ->
    gen_server:call(?MODULE, {get_state}).

subscribe() ->
    gen_server:cast(?MODULE, {subscribe, self()}).

unsubscribe() ->
    gen_server:cast(?MODULE, {unsubscribe, self()}).

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
    application:ensure_started(isis),
    %% Register with no IP address for this application...
    GI = #isis_geninfo_client{
	    app = ?HOSTINFO_APPID,
	    encode_func = fun encode_tlv/1,
	    decode_func = fun decode_tlv/2,
	    mergetype_func = fun mergetype_tlv/1
	   },
    isis_geninfo:register_client(GI),
    State1 = set_initial_state(),
    State2 = start_timer(State1),
    isis_geninfo:announce(State2#state.tlvs),
    dnssd:start(),
    dnssd:browse("_workstation._tcp"),
    {ok, State2}.

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
handle_call({get_state}, _From, State) ->
    {reply, State, State};
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
handle_cast({subscribe, Pid}, #state{hosts = Hosts, clients = C} = State) ->
    erlang:monitor(process, Pid),
    lists:map(
      fun({H, T}) -> notify_client(build_message({add, H, T}), Pid) end,
      dict:to_list(Hosts)),
    {noreply, State#state{clients = dict:store(Pid, [], C)}};
handle_cast({unsubscribe, Pid}, State) ->
    {noreply, remove_client(Pid, State)};
handle_cast(Msg, State) ->
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
%%-------------------------------------------------------------------
handle_info({add, LSP, HostInfo}, State) ->
    NewState = add_to_host(LSP, HostInfo, State),
    {noreply, NewState};
handle_info({delete, LSP, HostInfo}, State) ->
    NewState = delete_from_host(LSP, HostInfo, State),
    {noreply, NewState};
handle_info({timeout, _Ref, refresh}, State) ->
    NextState = refresh_tlvs(State),
    {noreply, start_timer(NextState)};
handle_info({'DOWN', _, process, Pid, _}, State) ->
    {noreply, remove_client(Pid, State)};
handle_info({dnssd, _Ref, {browse, add, {ServiceName, ServiceType, Domain}}}, State) ->
    NewDNS =
	[#hostinfo_dnssd{service_name = ServiceName,
			 service_type = ServiceType,
			 service_domain = Domain}
	 | State#state.dnssd_tlvs],
    {noreply, State#state{dnssd_tlvs = NewDNS}};
handle_info(Info, State) ->
    lager:error("Failed to handle info msg ~p", [Info]),
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
terminate(_Reason, State) ->
    %% Command all our ws clients to delete all data...
    Message = list_to_binary(
		json2:encode({struct, [{"command", "stop"}]})),
    notify_clients(Message, State),
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
get_hostinfo() ->
    {ok, Hostname} = inet:gethostname(),
    Processor = os:cmd("uname -p"),
    MemUsed = erlang:memory(processes_used),
    [
     #hostinfo_hostname{hostname = Hostname},
     #hostinfo_processor{processor = Processor},
     #hostinfo_memused{memory_used = MemUsed}
    ].
    
set_initial_state() ->
    TLVs = get_hostinfo(),
    #state{hosts = dict:new(),
	   clients = dict:new(),
	   tlvs = lists:sort(TLVs)}.

refresh_tlvs(#state{tlvs = TLVs, dnssd_tlvs = DNSSD} = State) ->
    NewTLVs = lists:sort(get_hostinfo()),
    isis_geninfo:announce(lists:subtract(NewTLVs, TLVs) ++ DNSSD),
    State#state{tlvs = NewTLVs}.

start_timer(State) ->
    T = erlang:start_timer(isis_protocol:jitter(?HOSTINFO_REFRESH_TIME, ?HOSTINFO_JITTER),
			   self(), refresh),
    State#state{refresh_timer = T}.

%%%===================================================================
%%% Host/WS Subscription service handlers, used by hostinfo_feed
%%%===================================================================
remove_client(Pid, #state{clients = C} = State) ->
    NewC =
	case dict:find(Pid, C) of
	    {ok, _Value} ->
		dict:erase(Pid, C);
	    error -> C
	end,
    State#state{clients = NewC}.

build_message({add, Host, TLVs}) ->
    HostID =
	lists:flatten(io_lib:format("~4.16.0B.~4.16.0B.~4.16.0B",
				    [X || <<X:16>> <= Host])),
    TLVAs = build_message_tlvs(TLVs),
    list_to_binary(
      json2:encode({struct, [{"command", "add"},
			     {"hostid", HostID},
			     {"host", isis_system:lookup_name(Host)},
			     {"tlvs", {struct, TLVAs}}]}));
build_message({delete, Host}) ->
    HostID =
	lists:flatten(io_lib:format("~4.16.0B.~4.16.0B.~4.16.0B",
				    [X || <<X:16>> <= Host])),
    list_to_binary(
      json2:encode({struct, [{"command", "delete"},
			     {"hostid", HostID}]})).

build_message_tlvs(TLVs) ->
    Converted =  lists:map(fun pp_hostinfo_tlv/1, TLVs),
    D = 
	lists:foldl(
	  fun({Key, Value}, Acc) ->
		  case dict:find(Key, Acc) of
		      {ok, OldValue} ->
			  dict:store(Key, OldValue ++ ", " ++ Value, Acc);
		      _ ->
			  dict:store(Key, Value, Acc)
		  end
	  end, dict:new(), Converted),
    dict:to_list(D).

notify_clients(Message, #state{clients = C}) ->
    Pids = dict:fetch_keys(C),
    lists:foreach(
      fun(Pid) -> notify_client(Message, Pid) end,
      Pids).

notify_client(Message, Pid) ->
    Pid ! {host_update, Message}.

%%%===================================================================
%%% Host database updates
%%%===================================================================
add_to_host(<<Host:6/binary, _:16>>, HostInfo,
	    #state{hosts = Hs} = State) ->
    DelTypes =
	lists:filter(fun(E1) -> lists:member(E1, ?HOSTINFO_SINGLE_TLVS) end,
		     lists:usort(
		       lists:map(fun(E) -> element(1, E) end,
				 HostInfo))),
    PrevTs =
	case dict:find(Host, Hs) of
	    {ok, Ts} -> sets:from_list(
			  lists:filter(
			    fun(T1) -> not lists:member(element(1, T1), DelTypes) end,
			    Ts));
	    _ -> sets:new()		 
	end,
    NewTs = 
	lists:foldl(
	  fun(T, Acc) -> sets:add_element(T, Acc) end,
	  PrevTs, HostInfo),
    R = sets:to_list(NewTs),
    notify_clients(build_message({add, Host, R}), State),
    State#state{hosts = dict:store(Host, R, Hs)}.

delete_from_host(<<Host:6/binary, _:16>>, HostInfo,
		 #state{hosts = Hs} = State) ->
    NewDict = 
	case dict:find(Host, Hs) of
	    {ok, Ts} ->
		S = sets:from_list(Ts),
		NewTs = 
		    sets:to_list(
		      lists:foldl(
			fun(T, Acc) -> sets:del_element(T, Acc) end,
			S, HostInfo)),
		case length(NewTs) of
		    0 -> notify_clients(build_message({delete, Host}), State),
			 dict:erase(Host, Hs);
		    _ -> notify_clients(build_message({add, Host, NewTs}), State),
			 dict:store(Host, NewTs, Hs)
		end;
	    _ -> Hs
	end,
    State#state{hosts = NewDict}.			  
					   	      
%%%===================================================================
%%% TLV encode/decode/dump functions
%%%===================================================================
encode_tlv(#hostinfo_hostname{hostname = H}) ->
    encode_tlv(1, erlang:list_to_binary(H));
encode_tlv(#hostinfo_processor{processor = P}) ->
    encode_tlv(2, erlang:list_to_binary(P));
encode_tlv(#hostinfo_memused{memory_used = M}) ->
    encode_tlv(3, <<M:64>>);
encode_tlv(#hostinfo_dnssd{service_name = N,
			   service_type = T,
			   service_domain = D}) ->
    NL = byte_size(N),
    TL = byte_size(T),
    DL = byte_size(D),
    encode_tlv(4, <<NL:8, N/binary, TL:8, T/binary, DL:8, D/binary>>).

encode_tlv(T, V) ->
    S = byte_size(V),
    <<T:8,S:8,V/binary>>.

decode_tlv(1, Value) ->
    #hostinfo_hostname{hostname = erlang:binary_to_list(Value)};
decode_tlv(2, Value) ->
    #hostinfo_processor{processor = erlang:binary_to_list(Value)};
decode_tlv(3, <<M:64>>) ->
    #hostinfo_memused{memory_used = M};
decode_tlv(4, <<NL:8, N:NL/binary, TL:8, T:TL/binary, DL:8, D:DL/binary>>) ->
    #hostinfo_dnssd{service_name = N,
		    service_type = T,
		    service_domain = D}.

%% 1 TLV per type in hostinfo, so we replace Though with the dns-sd
%% stuff, we must match exactly as we can have multiple of the same
%% type of TLV
mergetype_tlv(#hostinfo_hostname{}) -> replace;
mergetype_tlv(#hostinfo_processor{}) -> replace;
mergetype_tlv(#hostinfo_memused{}) -> replace;
mergetype_tlv(#hostinfo_dnssd{}) -> match.


pp_hostinfo_tlv(#hostinfo_hostname{hostname = H}) ->
    {"Hostname", H};
pp_hostinfo_tlv(#hostinfo_processor{processor = P}) ->
    {"Processor", P};
pp_hostinfo_tlv(#hostinfo_memused{memory_used = M}) ->
    {"Memory Used", lists:flatten(io_lib:format("~p", [M]))};
pp_hostinfo_tlv(#hostinfo_dnssd{service_name = N,
				service_type = T,
				service_domain = D}) ->
    {"dns-sd", lists:flatten(
		 io_lib:format("~s ~s ~s",
			       [binary_to_list(N),
				binary_to_list(T),
				binary_to_list(D)]))}.
