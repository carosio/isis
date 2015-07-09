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
%%% Created : 08 Dec 2014 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------
-module(isis_netconf).

-behaviour(gen_server).

-include_lib("xmerl/include/xmerl.hrl").
-include("isis_protocol.hrl").
-include("isis_system.hrl").
-include("spf_summary.hrl").

%% API
-export([start_link/0, get_state/0]).

-compile(export_all).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE).
-define(ISIS_NETCONF_NAMESPACES,
	[
	 {"rt", "urn:ietf:params:xml:ns:yang:ietf-routing"},
	 {"v4ur", "urn:ietf:params:xml:ns:yang:ietf-ipv4-unicast-routing"},
	 {"v6ur", "urn:ietf:params:xml:ns:yang:ietf-ipv6-unicast-routing"},
	 {"isis", "urn:ietf:params:xml:ns:yang:ietf-isis"}
	]
       ).

-define(ISIS_XML_BASE,
	"/rt:routing/rt:routing-instance[rt:name=\"default\"]/rt:routing-protocols/rt:routing-protocol[rt:type=\"isis:isis\"]/isis:isis/isis:instance").

-define(ISIS_Configurators,
	[
%	 {"//isis:system-id", fun apply_system_id/3},
%	 {"//isis:area-address", fun apply_area_address/3},
	 {"./isis:interfaces", fun apply_interfaces/3},
	 {"./isis:interfaces/isis:interface/isis:priority/isis:value",
		fun apply_interface_priority/3},
	 {"./isis:interfaces/isis:interface/isis:metric/isis:value",
		fun apply_interface_metric/3}
	]
       ).

-record(state, {
	  socket,
	  message_buffer = <<>>,
	  last_message,
	  enabled_interfaces = sets:new()
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
    {ok, #state{}, 5000}.

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
handle_info({tcp, _Port, Bytes}, State) ->
    {noreply, handle_data(Bytes, State)};
handle_info({tcp_closed, _Port}, State) ->
    isis_logger:warning("Netconf: connection to server was closed"),
    {noreply, handle_close(State), 30000};
handle_info(timeout, State) ->
    isis_logger:debug("Netconf: Connecting to Netopeer..."),
    case gen_tcp:connect({0,0,0,0,0,0,0,1}, 8301, []) of
	{ok, Socket} ->
	    {noreply, State#state{socket = Socket}};
        Other ->
	    isis_logger:error("Netconf: Could not connect to netconf server: ~p", [Other]),
	    {noreply, State#state{socket = undefined}, 30000}
    end;
handle_info(Info, State) ->
    isis_logger:debug("Received unknown info: ~p", [Info]),
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
send_message(Code, Data, State) when is_list(Data) ->
    send_message(Code, list_to_binary(Data), State);
send_message(Code, Data, #state{socket = Socket} = State) ->
    DataLen = byte_size(Data),
    ok = gen_tcp:send(Socket, <<Code:32, DataLen:32, Data/binary>>),
    State.

handle_data(Bytes, #state{message_buffer = MB} = State) ->
    BytesBin = list_to_binary(Bytes),
    NewMB = <<MB/binary, BytesBin/binary>>,
    parse_message(NewMB, State).

parse_message(<<Code:32, Len:32, Data:Len/binary, R/binary>>, State) ->
    NewState = process_message(Code, Data, State),
    parse_message(R, NewState);
parse_message(MB, State) ->
    State#state{message_buffer = MB}.

process_message(0, XML, State) -> % Config request
    isis_logger:info("Netconf: Received a configuration request"),
    %% Parse XML
    {ParsedXML, []} = xmerl_scan:string(binary_to_list(XML),
					[{namespace_conformant, true}]),
    NewState = process_config(ParsedXML, State),
    %% Done
    send_message(1, <<>>, NewState#state{last_message = ParsedXML});
process_message(3, _Data, State) -> % State request
    isis_logger:info("Netconf: Received a state request"),
    {ok, Reply} = process_state(State),
    send_message(4, Reply, State);
process_message(Code, _Data, State) ->
    isis_logger:warning("Netconf: Received unknown message with code: ~p", [Code]),
    State.

handle_close(State) ->
    State#state{socket = undefined}.

process_config(ParsedXML, State) ->
    case xpath(?ISIS_XML_BASE, ParsedXML) of
	[] ->
	    isis_logger:info("Netconf: did not find IS-IS config node."),
	    State;
	[Config] ->
	    isis_logger:info("Netconf: found IS-IS config node, processing..."),
	    lists:foldl(fun(Line, StateAcc) ->
			  configurator(Line, ParsedXML, Config, StateAcc)
		        end, State, ?ISIS_Configurators);
	_ ->
	    isis_logger:info("Netconf: multiple instances not supported yet."),
	    State
    end.

get_namespace_uri(Prefix) ->
    {Prefix, Uri} = lists:keyfind(Prefix, 1, ?ISIS_NETCONF_NAMESPACES),
    Uri.

process_state(State) ->
    MainNamespace = #xmlAttribute{name = 'xmlns', value = get_namespace_uri("rt")},
    Namespaces = lists:map(fun({Prefix, Url}) ->
			       #xmlAttribute{
				   name = list_to_atom("xmlns:" ++ Prefix),
				   value = Url
			       }
			   end, ?ISIS_NETCONF_NAMESPACES),
    Root = #xmlElement{
	name = 'routing-state',
	attributes = [MainNamespace | Namespaces],
	content = [
	    #xmlElement{name = 'routing-instance', content = [
		leaf(name, "default"),
		leaf(id, 1),
		leaf(type, "rt:default-routing-instance"),
		#xmlElement{name = 'default-ribs', content = [
		    #xmlElement{name = 'default-rib', content = [
			leaf('address-family', "ipv6"),
			leaf('rib-name', "main-ipv6")
		    ]},
		    #xmlElement{name = 'default-rib', content = [
			leaf('address-family', "ipv4"),
			leaf('rib-name', "main-ipv4")
		    ]}
		]},
		#xmlElement{name = 'interfaces', content = []}, %% TODO: Figure out which program populates this
		#xmlElement{name = 'routing-protocols', content = [
		    #xmlElement{name = 'routing-protocol', content = [
			leaf(type, "isis:isis"),
			leaf(name, "AutoISIS"),
			leaf('route-preference', 100),
			#xmlElement{name = 'isis', content = get_isis_state(State), attributes = [
			    #xmlAttribute{name = 'xmlns', value = get_namespace_uri("isis")}
			]}
		    ]}
		]}
	    ]}
	]
    },
    {ok, xmerl:export([Root], xmerl_xml)}.

%% This function should return [#xmlElement] for the subtree
%% routing-state/routing-instance/routing-protocols/isis subtree
get_isis_state(_State) ->
    [
	#xmlElement{name = 'system-counters', content = []},
	#xmlElement{name = 'interface-counters', content = []},
	#xmlElement{name = 'packet-counters', content = []},
	#xmlElement{name = 'interfaces', content = get_interface_state()},
	#xmlElement{name = 'adjacencies', content = get_adjacency_state()},
	#xmlElement{name = 'spf-log', content = get_spf_log()},
	#xmlElement{name = 'lsp-log', content = get_lsp_log()},
	#xmlElement{name = 'database', content = get_database_state()},
	#xmlElement{name = 'hostnames', content = get_hostnames_state()}
    ].

%% Helper that generates a text element
leaf(Name, Content) when is_integer(Content) ->
    leaf(Name, integer_to_list(Content));
leaf(Name, Content) ->
    #xmlElement{name = Name, content = [
        #xmlText{value = lists:flatten(Content)}
    ]}.

%% Generates an XML element like <level>1</level> from a given atom
%% which should either be level_1 or level_2.
level_number(level_1) ->
    leaf(level, 1);
level_number(level_2) ->
    leaf(level, 2).

level_enum(Name, level_1) ->
    leaf(Name, "level-1");
level_enum(Name, level_2) ->
    leaf(Name, "level-2");
level_enum(Name, "level_1_2") ->
    leaf(Name, "level-all").

id_to_text(<<ID:6/binary>>) ->
    io_lib:format("~4.16.0B.~4.16.0B.~4.16.0B", [X || <<X:16>> <= ID]);
id_to_text(<<Head:6/binary, PN:8>>) ->
    io_lib:format("~s.~2.16.0B", [id_to_text(Head), PN]);
id_to_text(<<Head:7/binary, Frag:8>>) ->
    io_lib:format("~s-~2.16.0B", [id_to_text(Head), Frag]).

mac_to_text(<<Mac:6/binary>>) ->
    io_lib:format("~2.16.0B:~2.16.0B:~2.16.0B:~2.16.0B:~2.16.0B:~2.16.0B",
		  [ X || <<X:8>> <= Mac ]).

fmap(Function, List) ->
    Intermediate = lists:map(Function, List),
    lists:filter(fun (undefined) -> false;
                     (_) -> true
                 end, Intermediate).

%% Helper to generate state that is a list with one entry per level
perlevel_state(LevelStateFun) ->
    fmap(LevelStateFun, [level_1,level_2]).

smiv2_ticks(undefined) ->
    0;
smiv2_ticks(Timestamp) ->
    StartUp = isis_system:get_state(startup_time),
    Ticks = round(timer:now_diff(Timestamp, StartUp) / 10000),
    if
	Ticks < (1 bsl 32) ->
	    Ticks;
	true ->
	    0
    end.

get_interface_adjacency_state(#isis_interface{name = Name, pid = IP},
			      Acc) when is_pid(IP) ->
    LPids = [
	{level_1, isis_interface:get_level_pid(IP, level_1)},
	{level_2, isis_interface:get_level_pid(IP, level_2)}
    ],
    Acc ++ lists:foldl(
	fun({Level, LPid}, Acc1) when is_pid(LPid) ->
	    AH = dict:to_list(isis_interface_level:get_state(LPid, adjacencies)),
	    Acc1 ++ lists:map(
		fun({Mac, {Sid, AdjPid}}) ->
		    ISType = isis_adjacency:get_state(AdjPid, is_type),
		    NeighborLevel = if
			ISType =:= level_1; ISType =:= level_2; ISType =:= level_1_2 ->
			    [level_enum('neighbor-level', ISType)];
			true ->
			    []
		    end,
		    HoldTimer = isis_adjacency:get_state(AdjPid, timer),
		    HoldTimerElement = if
		        is_integer(HoldTimer) ->
			    [leaf('hold-timer', round(HoldTimer / 1000))];
			true ->
			    []
		    end,
		    Priority = isis_adjacency:get_state(AdjPid, priority),
		    PriorityElement = if
			is_integer(Priority) ->
			    [leaf('neighbor-priority', Priority)];
			true ->
			    []
		    end,
		    LastUpTime = smiv2_ticks(isis_adjacency:get_state(AdjPid, last_uptime)),
		    StateMap = [{new, "Init"}, {init, "Init"}, {up, "Up"}, {down, "Down"}],
		    State = proplists:get_value(isis_adjacency:get_state(AdjPid), StateMap),
		    StateElement = if
			is_list(State) ->
			    [leaf('state', State)];
			true ->
			    []
		    end,
		    #xmlElement{
			name = 'adjacency',
			content = [
			    leaf('interface', Name),
			    level_enum('level', Level),
			    leaf('neighbor-sysid', id_to_text(Sid) ++ ".00"),
			    %% TODO: Do we support extended circuit-id?
			    leaf('neighbor-snpa', mac_to_text(Mac))
			] ++ NeighborLevel ++ HoldTimerElement ++ PriorityElement ++ [
			    leaf('lastuptime', LastUpTime)
			] ++ StateElement
		    }
		end, AH);
	(_, Acc1) ->
	    Acc1
	end, [], LPids);
get_interface_adjacency_state(#isis_interface{} = _, Acc) ->
    Acc.

%% Formats current IS-IS interfaces to [#xmlElement] for subtree
%% routing-state/routing-instance/routing-protocols/isis/adjacencies
get_adjacency_state() ->
    Interfaces = isis_system:list_interfaces(),
    lists:foldl(fun get_interface_adjacency_state/2, [], Interfaces).

%% Formats current IS-IS interfaces to [#xmlElement] for subtree
%% routing-state/routing-instance/routing-protocols/isis/lsp-log
get_lsp_log() ->
    FormatLSP = fun({add, Level, #isis_lsp{} = LSP, Time, Id}) ->
	#xmlElement{
	    name = 'event',
	    content = [
		leaf('id', Id),
		level_number(Level),
		#xmlElement{
		    name = 'lsp',
		    content = [
			leaf('lsp', id_to_text(LSP#isis_lsp.lsp_id)),
			leaf('sequence', LSP#isis_lsp.sequence_number)
		    ]
		},
		leaf('received-timestamp', smiv2_ticks(Time))
	    ]
	};
      %% XXX: The model for the lsp log is not that good, it is
      %% Missing a way to convey what actually happened to the LSP
      %% so with that, it might be better not to log deleted LSPs.
      ({delete, _Level, _LSP_ID, _Time, _Id}) ->
	undefined
    end,
    fmap(FormatLSP, isis_lspdb_log:get_log(level_1))
      ++ fmap(FormatLSP, isis_lspdb_log:get_log(level_2)).

%% Formats current IS-IS interfaces to [#xmlElement] for subtree
%% routing-state/routing-instance/routing-protocols/isis/spf-log
get_spf_log() ->
    FormatSPF = fun({_Time, Level, _Table, _Reason, ExtInfo}) ->
	TypeMap = [{full, "full"}],
	Type = proplists:get_value(ExtInfo#spf_ext_info.spf_type, TypeMap),
	#xmlElement{
	    name = 'event',
	    content = [
		leaf('id', ExtInfo#spf_ext_info.id),
		leaf('spf-type', Type),
		level_number(Level),
		leaf('spf-delay', ExtInfo#spf_ext_info.delayed),
		leaf('schedule-timestamp', smiv2_ticks(ExtInfo#spf_ext_info.scheduled)),
		leaf('start-timestamp', smiv2_ticks(ExtInfo#spf_ext_info.started)),
		leaf('end-timestamp', smiv2_ticks(ExtInfo#spf_ext_info.ended))
		%% TODO: Get trigger-lsp info from SPF and format it
	    ]
	}
    end,
    lists:map(FormatSPF, spf_summary:last_runs(level_1))
      ++ lists:map(FormatSPF, spf_summary:last_runs(level_2)).


format_interface_state(#isis_interface{name = Name, pid = Pid})
	when is_pid(Pid) ->
    %% XXX: The current model only accommodates a single Circuit-ID.
    %% "Merging" them is obviously not optimal.
    L1CircuitId = isis_interface:get_state(Pid, level_1, pseudonode),
    L2CircuitId = isis_interface:get_state(Pid, level_2, pseudonode),
    CircuitId = if
	is_integer(L1CircuitId), L1CircuitId =/= 0 ->
	    L1CircuitId;
	is_integer(L2CircuitId), L2CircuitId =/= 0 ->
	    L2CircuitId;
	true ->
	    0
    end,
    L1Pid = isis_interface:get_level_pid(Pid, level_1),
    L2Pid = isis_interface:get_level_pid(Pid, level_2),
    Level = if
	is_pid(L1Pid), is_pid(L2Pid) ->
	    "level-all";
	is_pid(L1Pid) ->
	    "level-1";
	is_pid(L2Pid) ->
	    "level-2";
	true ->
	    undefined
    end,
    case Level of
	undefined ->
	    undefined;
	_ ->
	    #xmlElement{
		name = 'interfaces',
		content = [
		    leaf('interface', Name),
		    leaf('circuit-id', CircuitId),
		    %% TODO: I could not figure out how to get admin-state and oper-state
		    %% from here.
		    %% zclient puts something into #isis_interface.flags while isis_netlink
		    %% seems to set #isis_interface.enabled
		    leaf('interface-type', "broadcast"), %% We don't seem to support anything else?
		    leaf('level', Level)
		    %% Passive and Three-Way-Handshake don't seem to be supported
		]
	    }
   end;
format_interface_state(#isis_interface{} = _) ->
    undefined.

%% Formats current IS-IS interfaces to [#xmlElement] for subtree
%% routing-state/routing-instance/routing-protocols/isis/interfaces
get_interface_state() ->
    fmap(fun format_interface_state/1,
	 isis_system:list_interfaces()).

%% Formats current database to [#xmlElement] for subtree
%% routing-state/routing-instance/routing-protocols/isis/database
get_database_state() ->
    perlevel_state(fun get_level_database_state/1).

get_level_database_state(Level) ->
    LSPs = ets:tab2list(isis_lspdb:get_db(Level)),
    LSPElements = lists:map(fun format_lsp/1, LSPs),
    #xmlElement{
	name = 'level-db',
	content = [ level_number(Level) | LSPElements ]
    }.

%% Formats a string for the yang type bits. To be
%% called with a list [{BitName,boolean()}] as argument.
yang_bits(KVList) ->
    Bits = fmap(fun({_,false}) ->
			undefined;
		   ({Key,true}) ->
			Key
		end, KVList),
    string:join(Bits, " ").

format_lsp(LSP) ->
    LSPID = id_to_text(LSP#isis_lsp.lsp_id),
    Now = isis_protocol:current_timestamp(),
    RL = LSP#isis_lsp.remaining_lifetime - (Now - LSP#isis_lsp.last_update),
    RLCapped = if
	RL >= 0 ->
		RL;
	true ->
		0
    end,
    Attributes = yang_bits([
	{"PARTITIONED", LSP#isis_lsp.partition},
	{"OVERLOAD", LSP#isis_lsp.overload}
    ]),

    #xmlElement{
	name = 'lsp',
	content = [
	    leaf('lsp-id', LSPID),
	    leaf('checksum', LSP#isis_lsp.checksum),
	    leaf('remaining-lifetime', RLCapped),
	    leaf('sequence', LSP#isis_lsp.sequence_number),
	    leaf('attributes', Attributes)
	] ++ format_tlvs(LSP#isis_lsp.tlv)
    }.

format_metric({Name, #isis_metric_information{
			    metric_supported = Supported,
			    metric = Metric 
		     }}) ->
    case Supported of
	false -> undefined;
	    _ -> #xmlElement{
		     name = Name,
		     content = [
			 leaf(metric, Metric),
			 leaf(supported, "true")
		 ]}
    end.

format_is_reach(#isis_tlv_is_reachability_detail{
			neighbor = NID,
			default = DM
		} = Neighbor) ->
    External = case DM#isis_metric_information.metric_type of
	internal -> "true";
	       _ -> "false"
    end,
    #xmlElement{
	name = 'neighbor',
	content = [
	    leaf('neighbor-id', id_to_text(NID)),
	    leaf('i-e', External),
	    leaf('default-metric', DM#isis_metric_information.metric)
	] ++ fmap(fun format_metric/1, [
			{'delay-metric', Neighbor#isis_tlv_is_reachability_detail.delay},
			{'expense-metric', Neighbor#isis_tlv_is_reachability_detail.expense},
			{'error-metric', Neighbor#isis_tlv_is_reachability_detail.error}
	])
    }.

grouping_prefix_ipv4_std(Addr, Mask, DefaultM, DelayM, ExpenseM, ErrorM) ->
    External = case DefaultM#isis_metric_information.metric_type of
	internal -> "true";
	       _ -> "false"
    end,
    [
	%% TODO: up/down bit
	leaf('i-e', External),
	leaf('ip-prefix', isis_system:address_to_string(ipv4, Addr)),
	leaf('prefix-len', isis_lspdb:count_leading_ones(Mask)),
	leaf('default-metric', DefaultM#isis_metric_information.metric)
    ] ++ fmap(fun format_metric/1, [
		{'delay-metric', DelayM},
		{'expense-metric', ExpenseM},
		{'error-metric', ErrorM}
    ]).

format_ip_internal_reach(#isis_tlv_ip_internal_reachability_detail{
				ip_address = Addr,
				subnet_mask = Mask,
				default = DefaultM,
				delay = DelayM,
				expense = ExpenseM,
				error = ErrorM
			 }) ->
    #xmlElement{
	name = 'prefixes',
	content = grouping_prefix_ipv4_std(Addr, Mask, DefaultM,
					   DelayM, ExpenseM, ErrorM)
    }.

-record(ext_reach_subtlv_state, {
		tag = [],
		tag64 = []
}).
ext_reach_subtlv(#isis_subtlv_eir_admintag32{tag = Tag},
		 #ext_reach_subtlv_state{tag = Out} = Acc) ->
    Acc#ext_reach_subtlv_state{
	tag = Out ++ leaf('tag', Tag)
    };
ext_reach_subtlv(#isis_subtlv_eir_admintag64{tag = Tag},
		 #ext_reach_subtlv_state{tag64 = Out} = Acc) ->
    Acc#ext_reach_subtlv_state{
	tag64 = Out ++ leaf('tag64', Tag)
    };
ext_reach_subtlv(Other, Acc) ->
    isis_logger:debug("Netconf: unsupported sub-TLV: ~p", [Other]),
    Acc.

format_ip_ext_reach_subtlv(SubTLVs) ->
    Acc = lists:foldl(fun ext_reach_subtlv/2, #ext_reach_subtlv_state{}, SubTLVs),
    Acc#ext_reach_subtlv_state.tag ++ Acc#ext_reach_subtlv_state.tag64.

format_ip_extended_reach(#isis_tlv_extended_ip_reachability_detail{
				prefix = Prefix,
				mask_len = PrefixLen,
				metric = Metric,
				up = UpDown,
				sub_tlv = SubTLVs
			 }) ->
    UpDownText = case UpDown of
	true -> "false";
	_    -> "true"
    end,
    #xmlElement{
	name = 'prefixes',
	content = [
	    leaf('ip-prefix', isis_system:address_to_string(ipv4, Prefix)),
	    leaf('prefix-len', PrefixLen),
	    leaf('up-down', UpDownText),
	    leaf('metric', Metric)
	] ++ format_ip_ext_reach_subtlv(SubTLVs)
    }.

-record(ipv6_reach_subtlv_state, {
		tag = [],
		tag64 = [],
		source_prefix = undefined
}).
ipv6_reach_subtlv(#isis_subtlv_eir_admintag32{tag = Tag},
		  #ipv6_reach_subtlv_state{tag = Out} = Acc) ->
    Acc#ipv6_reach_subtlv_state{
	tag = Out ++ leaf('tag', Tag)
    };
ipv6_reach_subtlv(#isis_subtlv_eir_admintag64{tag = Tag},
		  #ipv6_reach_subtlv_state{tag64 = Out} = Acc) ->
    Acc#ipv6_reach_subtlv_state{
	tag64 = Out ++ leaf('tag64', Tag)
    };
ipv6_reach_subtlv(#isis_subtlv_srcdst{prefix = Prefix, prefix_length = PrefixLength},
		  #ipv6_reach_subtlv_state{source_prefix = undefined} = Acc) ->
    Acc#ipv6_reach_subtlv_state{
	source_prefix = #xmlElement{
	    name = 'source-prefix',
	    content = [
		leaf('ip-prefix', isis_system:address_to_string(ipv6, Prefix)),
		leaf('prefix-len', PrefixLength)
	    ]
	}
    };
ipv6_reach_subtlv(#isis_subtlv_srcdst{} = _, Acc) ->
    isis_logger:warning("Netconf: multiple srcdest sub-TLVs in TLV"),
    Acc;
ipv6_reach_subtlv(Other, Acc) ->
    isis_logger:debug("Netconf: unsupported sub-TLV: ~p", [Other]),
    Acc.

format_ipv6_reach_subtlv(SubTLVs) ->
    Acc = lists:foldl(fun ipv6_reach_subtlv/2, #ipv6_reach_subtlv_state{}, SubTLVs),
    Elements = [
	Acc#ipv6_reach_subtlv_state.source_prefix
    ] ++ Acc#ipv6_reach_subtlv_state.tag ++ Acc#ipv6_reach_subtlv_state.tag64,
    lists:filter(fun(undefined) -> false;
		    (_)         -> true
		 end, Elements).

format_ipv6_reach(#isis_tlv_ipv6_reachability_detail{
			metric = Metric,
			up = UpDown,
			external = _External,
			mask_len = PrefixLen,
			prefix = Prefix,
			sub_tlv = SubTLVs
		 }) ->
    UpDownText = case UpDown of
	true -> "false";
	_    -> "true"
    end,
    #xmlElement{
	name = 'prefixes',
	content = [
	    leaf('ip-prefix', isis_system:address_to_string(ipv6, Prefix)),
	    leaf('prefix-len', PrefixLen),
	    leaf('up-down', UpDownText),
	    leaf('metric', Metric)
	] ++ format_ipv6_reach_subtlv(SubTLVs)
    }.

-record (format_tlv_state, {
	    is_neighbors = [],
	    authentication = undefined,
	    extended_is_neighbors = [],
	    ipv4_internal_reach = [],
	    protocols_supported = [],
	    ipv4_external_reach = [],
	    ipv4_addresses = [],
	    ipv4_te_routerid = undefined,
	    ipv4_extended_reach = [],
	    dynamic_hostname = undefined,
	    ipv6_te_routerid = undefined,
	    ipv6_addresses = [],
	    ipv6_reach = []
}).

list_container(_Name, []) ->
    undefined;
list_container(Name, Content) ->
    #xmlElement{ name = Name, content = Content }.

format_tlvs(TLVs) ->
    Acc = lists:foldl(fun format_tlv/2, #format_tlv_state{}, TLVs),
    Elements = [
	list_container('is-neighbor', Acc#format_tlv_state.is_neighbors),
	Acc#format_tlv_state.authentication,
	list_container('extended-is-neighbor', Acc#format_tlv_state.extended_is_neighbors),
	list_container('ipv4-internal-reachability', Acc#format_tlv_state.ipv4_internal_reach)
    ] ++ Acc#format_tlv_state.protocols_supported ++ [
	list_container('ipv4-external-reachability', Acc#format_tlv_state.ipv4_external_reach)
    ] ++ Acc#format_tlv_state.ipv4_addresses ++ [
	Acc#format_tlv_state.ipv4_te_routerid,
	list_container('extended-ipv4-reachability', Acc#format_tlv_state.ipv4_extended_reach),
	Acc#format_tlv_state.dynamic_hostname,
	Acc#format_tlv_state.ipv6_te_routerid
    ] ++ Acc#format_tlv_state.ipv6_addresses ++ [
	list_container('ipv6-reachability', Acc#format_tlv_state.ipv6_reach)
    ],
    lists:filter(fun(undefined) -> false;
                    (_)         -> true
                 end, Elements).

format_tlv(#isis_tlv_is_reachability{is_reachability = R},
	   #format_tlv_state{is_neighbors = Out} = Acc) ->
    Acc#format_tlv_state{
	is_neighbors = Out ++ lists:map(fun format_is_reach/1, R)
    };
format_tlv(#isis_tlv_authentication{type = Type, signature = Signature},
	   #format_tlv_state{authentication = undefined} = Acc) ->
    {OutputType, OutputKey} = case Type of
	text -> { "plaintext", crypto:hash(md5,Signature) };
	md5 -> { "message-digest", Signature};
	_ -> { "none", Signature } %% XXX: Maybe allow for something better in the model?
    end,
    Acc#format_tlv_state{
	authentication = #xmlElement{name = 'authentication', content = [
	    leaf('authentication-type', OutputType),
	    leaf('authentication-key', OutputKey)
        ]}
    };
format_tlv(#isis_tlv_authentication{} = _, Acc) ->
    isis_logger:warning("Netconf: multiple authentication TLVs in LSP"),
    Acc;
format_tlv(#isis_tlv_extended_reachability{reachability = R},
	   #format_tlv_state{extended_is_neighbors = Out} = Acc) ->
    FormatExtReach = fun(#isis_tlv_extended_reachability_detail{
			      neighbor = NID,
			      metric = Metric
			 }) ->
	#xmlElement{
	    name = 'neighbor',
	    content = [
		leaf('neighbor-id', id_to_text(NID)),
		leaf('metric', Metric)
	    ]
	}
    end,
    Acc#format_tlv_state{
	extended_is_neighbors = Out ++ lists:map(FormatExtReach, R)
    };
format_tlv(#isis_tlv_ip_internal_reachability{ip_reachability = R},
	   #format_tlv_state{ipv4_internal_reach = Out} = Acc) ->
    Acc#format_tlv_state{
	ipv4_internal_reach = Out ++ lists:map(fun format_ip_internal_reach/1, R)
    };
format_tlv(#isis_tlv_protocols_supported{protocols = Protocols},
	   #format_tlv_state{protocols_supported = Out} = Acc) ->
    ProtoLeaf = fun (Protocol) ->
	leaf('protocol-supported', isis_enum:to_int(protocols, Protocol))
    end,
    Acc#format_tlv_state{
	protocols_supported = Out ++ lists:map(ProtoLeaf, Protocols)
    };
%format_tlv(#isis_tlv_ip_external_reach) %% TODO: This is required by the model, bleh.
format_tlv(#isis_tlv_ip_interface_address{addresses = Addresses},
	   #format_tlv_state{ipv4_addresses = Out} = Acc) ->
    AddrLeaf = fun(Address) ->
	leaf('ipv4-addresses', isis_system:address_to_string(ipv4, Address))
    end,
    Acc#format_tlv_state{
	ipv4_addresses = Out ++ lists:map(AddrLeaf, Addresses)
    };
format_tlv(#isis_tlv_te_router_id{router_id = ID},
	   #format_tlv_state{ipv4_te_routerid = undefined} = Acc) ->
    Acc#format_tlv_state{
	ipv4_te_routerid = leaf('ipv4-te-routerid',
				isis_system:address_to_string(ipv4, ID))
    };
format_tlv(#isis_tlv_te_router_id{} = _, Acc) ->
    isis_logger:warning("Netconf: multiple router ids in LSP"),
    Acc;
format_tlv(#isis_tlv_extended_ip_reachability{reachability = R},
	   #format_tlv_state{ipv4_extended_reach = Out} = Acc) ->
    Acc#format_tlv_state{
	ipv4_extended_reach = Out ++ lists:map(fun format_ip_extended_reach/1, R)
    };
format_tlv(#isis_tlv_dynamic_hostname{hostname = Hostname},
	   #format_tlv_state{dynamic_hostname = undefined} = Acc) ->
    Acc#format_tlv_state{
        dynamic_hostname = leaf('dynamic-hostname', Hostname)
    };
format_tlv(#isis_tlv_dynamic_hostname{} = _, Acc) ->
    isis_logger:warning("Netconf: multiple hostnames in LSP"),
    Acc;
%format_tlv(#isis_tlv_ipv6_te_router_id) %% TODO: This is required by the model
format_tlv(#isis_tlv_ipv6_interface_address{addresses = Addresses},
	   #format_tlv_state{ipv6_addresses = Out} = Acc) ->
    AddrLeaf = fun(Address) ->
	leaf('ipv6-addresses', isis_system:address_to_string(ipv6, Address))
    end,
    Acc#format_tlv_state{
	ipv6_addresses = Out ++ lists:map(AddrLeaf, Addresses)
    };
format_tlv(#isis_tlv_ipv6_reachability{reachability = R},
	   #format_tlv_state{ipv6_reach = Out} = Acc) ->
    Acc#format_tlv_state{
	ipv6_reach = Out ++ lists:map(fun format_ipv6_reach/1, R)
    };
format_tlv(Other, Acc) ->
    isis_logger:debug("Netconf: unsupported TLV: ~p", [Other]),
    Acc.

%% This function should return [#xmlElement] for the subtree
%% routing-state/routing-instance/routing-protocols/isis/hostnames
get_hostnames_state() ->
    HostNameGen = fun({SystemID, Name}) ->
	#xmlElement{name = 'hostname', content = [
	    leaf('system-id', id_to_text(SystemID) ++ ".00"),
	    leaf('hostname', Name)
	]}
    end,
    lists:map(HostNameGen, isis_system:all_names()).

configurator({Pattern, Applicator}, XML, Config, State) ->
    Nodes = xpath(Pattern, Config, Config#xmlElement.parents, XML, []),
    Apply = fun(N, StateAcc) -> Applicator(N, XML, StateAcc) end,
    lists:foldl(Apply, State, Nodes).

%%%===================================================================
%%% Configuration helpers
%%%===================================================================

xpath(Pattern, XML) ->
    xpath(Pattern, XML, []).
xpath(Pattern, XML, Options) ->
    xpath(Pattern, XML, [], XML, Options).
xpath(Pattern, Node, Parents, Doc, Options) ->
    DefaultOptions =
      [
       {namespace, ?ISIS_NETCONF_NAMESPACES}
      ],
    xmerl_xpath:string(Pattern, Node, Parents,
		       Doc, DefaultOptions ++ Options).

xml_get_value(text, Node) ->
    Content = Node#xmlElement.content,
    [T] =
	lists:filter(fun(#xmlText{}) ->
			     true;
			(_) ->
			 false
		     end, Content),
    T#xmlText.value;
xml_get_value(_, _) ->
    error.

extract_interface(Node, XML) ->
    Interface =
	xml_get_value(
	  text,
	  hd(xpath("../../../isis:interface/isis:name", Node,
		   Node#xmlElement.parents, XML, []))),
    string:strip(Interface, both, $").

read_leaf(Node, XML, Path) ->
    Leaf = hd(xpath(Path, Node, Node#xmlElement.parents, XML, [])),
    xml_get_value(text, Leaf).

extract_level(Node, XML) ->
    Level =
	xml_get_value(
	  text,
	  hd(xpath("../isis:level", Node,
		   Node#xmlElement.parents, XML, []))),
    case Level of
	"level-1" ->
	    level_1;
	"level-2" ->
	    level_2;
	"level-all" ->
	    level_1_2
    end.
    
%%%===================================================================
%%% Configuration functions
%%%===================================================================
apply_system_id(Node, _XML, State) ->
    Value = xml_get_value(text, Node),
    isis_logger:info("Netconf: Found system-id ~p", [Value]),
    ID = string:tokens(Value, "."),
    IDBint = 
	lists:map(
	  fun(X) when length(X) =:= 4 ->
		  <<(list_to_integer(X, 16)):16>>;
	     ("00") ->
		  <<>>
	  end, ID),
    SystemID = lists:foldl(fun(X, Acc) -> <<Acc/binary, X/binary>> end, <<>>, IDBint),
    isis_system:set_system_id(SystemID),
    State.

apply_area_address(Node, _XML, State) ->
    Value = xml_get_value(text, Node),
    isis_logger:info("Netconf: Found area address ~p", [Value]),
    AreaBits = string:tokens(Value, "."),
    AreaBin = 
	lists:map(
	  fun(X) when length(X) =:= 4 ->
		  <<(list_to_integer(X, 16)):16>>;
	     (X) when length(X) =:= 2 ->
		  <<(list_to_integer(X, 16)):8>>
	  end, AreaBits),
    Area = lists:foldl(fun(X, Acc) -> <<Acc/binary, X/binary>> end, <<>>, AreaBin),
    isis_system:add_area(Area),
    State.

apply_interfaces(Node, XML, State) ->
    EnabledInterfaces = sets:from_list(fmap(
	fun(#xmlElement{name = interface} = IF) ->
	    IFName = read_leaf(IF, XML, "./isis:name"),
	    IFEnabled = read_leaf(IF, XML, "./isis:enabled"),
	    case IFEnabled of
		"false" -> undefined;
		_  -> IFName
	    end;
	(_) ->
	    undefined
    end, Node#xmlElement.content)),
    isis_logger:info("Netconf: Enabled interfaces are ~p", [sets:to_list(EnabledInterfaces)]),
    ActiveInterfaces = sets:from_list(fmap(
	fun(#isis_interface{name = Name, pid = Pid}) when is_pid(Pid) ->
	    Name;
	(_) ->
	    undefined
    end, isis_system:list_interfaces())),
    DeleteInterfaces = sets:to_list(sets:subtract(ActiveInterfaces, EnabledInterfaces)),
    AddInterfaces = sets:to_list(sets:subtract(EnabledInterfaces, ActiveInterfaces)),
    isis_logger:info("Netconf: Stopping IS-IS on interfaces ~p", [DeleteInterfaces]),
    isis_logger:info("Netconf: Starting IS-IS on interfaces ~p", [AddInterfaces]),
    lists:map(fun(IF) ->
        isis_system:del_interface(IF)
    end, DeleteInterfaces),
    lists:map(fun(IF) ->
	isis_system:add_interface(IF),
	isis_system:enable_level(IF, level_1),
	isis_system:enable_level(IF, level_1),
	isis_system:set_interface(IF, level_1, [{metric, 1000000}]),
	isis_system:set_interface(IF, level_1, [{authentication, {text, <<"isis-autoconf">>}}])
    end, AddInterfaces),
    State#state{enabled_interfaces = EnabledInterfaces}.

apply_interface_priority(Node, XML, #state{enabled_interfaces = EnabledIFs} = State) ->
    %% TODO: Revert to default if leaf is absent
    Value = list_to_integer(xml_get_value(text, Node), 10),
    Interface = extract_interface(Node, XML),
    Level = extract_level(Node, XML),
    case sets:is_element(Interface, EnabledIFs) of
	true ->
	    isis_logger:info("Netconf: Setting interface ~s priority ~p for level ~p",
		       [Interface, Value, Level]),
	    isis_system:set_interface(Interface, Level, [{priority, Value}]);
	_ ->
	    ok
    end,
    State.

apply_interface_metric(Node, XML, #state{enabled_interfaces = EnabledIFs} = State) ->
    %% TODO: Revert to default if leaf is absent
    Value = list_to_integer(xml_get_value(text, Node), 10),
    Interface = extract_interface(Node, XML),
    Level = extract_level(Node, XML),
    case sets:is_element(Interface, EnabledIFs) of
	true ->
	    isis_logger:info("Netconf: Setting interface ~s metric ~p for level ~p",
		       [Interface, Value, Level]),
	    isis_system:set_interface(Interface, Level, [{metric, Value}]);
	_ ->
	    ok
    end,
    State.
