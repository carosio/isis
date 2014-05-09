%%%-------------------------------------------------------------------
%%% @author Rick Payne <rickp@rossfell.co.uk>
%%% @copyright (C) 2014, Alistair Woodman, California USA <awoodman@netdef.org>
%%% @doc
%%%
%%% Demo system, to poke some LSPs into the database and create some
%%% churn as if we had a real network.
%%%
%%% @end
%%% Created :  2 Apr 2014 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------
-module(demo).

-behaviour(gen_server).

-include("isis_system.hrl").
-include("isis_protocol.hrl").

%% API
-export([start_link/0, stop/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE).

-record(state, {
	  timer,        %% Our timer for events
	  nextstate,    %% Simple FSM...
	  sequence = 1  %% Next sequence number to use in LSPs
	 }).

%%%===================================================================
%%% API
%%%===================================================================
stop() ->
    gen_server:call(?MODULE, stop).

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
    Timer = erlang:start_timer(isis_protocol:jitter(20 * 1000, 50),
			       self(), ping),
    State = create_initial_state(),
    {ok, State#state{timer = Timer}}.

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
handle_call(stop, _From, State) ->
    {stop, normal, State};
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
handle_info({timeout, _Ref, ping}, State) ->
    NewState = next_demo(State),
    Timer = erlang:start_timer(isis_protocol:jitter(20 * 1000, 50),
			       self(), ping),
    {noreply, NewState#state{timer = Timer}};
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
create_initial_state() ->
    #state{nextstate = setup}.

next_demo(#state{nextstate = setup} = State) ->
    %% Create our 2 'gateway' nodes and cosy up to them...
    isis_system:add_sid_addresses(<<16#de, 16#ad, 16#be, 16#ef, 0, 0>>,
				  [55664433]),
    isis_system:add_sid_addresses(<<16#c0, 16#ff, 16#fe, 0, 0, 0>>,
				  [99887766]),
    DeadBeefTLV = #isis_tlv_extended_reachability{
		     reachability = [#isis_tlv_extended_reachability_detail{
					neighbor = <<16#de, 16#ad, 16#be, 16#ef, 0, 0, 0>>,
					metric = 1500, sub_tlv=[]}]},
    CoffeeTLV = #isis_tlv_extended_reachability{
		   reachability = [#isis_tlv_extended_reachability_detail{
				      neighbor = <<16#c0, 16#ff, 16#fe, 0, 0, 0, 0>>,
				      metric = 15000, sub_tlv=[]}]},
    isis_system:update_tlv(DeadBeefTLV, 0, level_1),
    isis_system:update_tlv(CoffeeTLV, 0, level_1),
    %% Now we stir up some LSPs
    NextState = generate_lsps(State),
    NextState#state{nextstate = running};
next_demo(#state{nextstate = running} = State) ->
    generate_lsps(State);
next_demo(_) ->
    stop.

generate_lsps(State) ->
    L = random_list(8),
    CoffeeNodes = lists:sublist(L, 1, 3),
    DeadBeefNodes = lists:sublist(L, 4, 3),
    TopNodes = lists:sublist(L, 7, 2),
    generate_coffee(CoffeeNodes, <<16#c0, 16#ff, 16#fe, 0, 0, 0>>,
		    lists:nth(1, TopNodes), State),
    generate_coffee(DeadBeefNodes, <<16#de, 16#ad, 16#be, 16#ef, 0, 0>>,
		    lists:nth(2, TopNodes), State),
    State#state{sequence = State#state.sequence + 1}.


generate_coffee(Nodes, Link, TN, State) ->
    Creator = 
	fun(N, Acc) ->
		NeighborID = <<N:16, 0, 0, 0, 0, 0>>,
		LSPID = <<NeighborID/binary, 0>>,
		Hostname = string:concat("injected-", integer_to_list(N)),
		PrefixBin = <<1:8, N:8, 0:16>>,
		<<Prefix:32>> = PrefixBin,
		{ReachabilityTLV, NewAcc} = 
		    case random:uniform() > 0.5 of
			true ->
			    {#isis_tlv_extended_reachability{
				reachability = [#isis_tlv_extended_reachability_detail{
						   neighbor = <<Link:6/binary, 0:8>>,
						   metric = erlang:trunc(random:uniform() * 1000),
						   sub_tlv = []},
						#isis_tlv_extended_reachability_detail{
						   neighbor = <<TN:16, 0, 0, 0, 0, 0>>,
						   metric = erlang:trunc(random:uniform() * 1000),
						   sub_tlv = []
						  }
					       ]},
			     Acc ++ [N]};
			_ ->
			    {#isis_tlv_extended_reachability{
				reachability = [#isis_tlv_extended_reachability_detail{
						   neighbor = <<Link:6/binary, 0:8>>,
						   metric = erlang:trunc(random:uniform() * 1000),
						   sub_tlv = []}]},
			     Acc}
		    end,
		L = #isis_lsp{
		       lsp_id = LSPID,
		       last_update = isis_protocol:current_timestamp(),
		       pdu_type = level1_lsp,
		       remaining_lifetime = 500,
		       sequence_number = State#state.sequence,
		       partition = false,
		       overload = false,
		       isis_type = level_1_2,
		       tlv = [#isis_tlv_area_address{areas = isis_system:areas()},
			      #isis_tlv_protocols_supported{protocols = [ipv4]},
			      #isis_tlv_dynamic_hostname{hostname = Hostname},
			      ReachabilityTLV,
			      #isis_tlv_extended_ip_reachability{
				 reachability = [#isis_tlv_extended_ip_reachability_detail{
						    prefix = Prefix,
						    mask_len = 24,
						    metric = 1,
						    up = true,
						    sub_tlv = []}]}
			     ]
		      },
		CSum = isis_protocol:checksum(L),
		{L#isis_lsp{checksum = CSum}, NewAcc}
	end,
    {LSPs, TNLinks} = lists:mapfoldl(Creator, [], Nodes),

    %% Now create the 'top' LSP to link to the ones that have randomly connected to us..
    LSPs2 =
	case length(TNLinks) > 0 of
	    true ->
		NNeighborID = <<TN:16, 0, 0, 0, 0, 0>>,
		NLSPID = <<NNeighborID/binary, 0>>,
		NHostname = string:concat("topnode-", integer_to_list(TN)),
		NPrefixBin = <<1:8, TN:8, 0:16>>,
		<<NPrefix:32>> = NPrefixBin,
		NReachabilityTLV = 
		    #isis_tlv_extended_reachability{
		       reachability = 
			   lists:map(fun(TNN) ->
					     #isis_tlv_extended_reachability_detail{
						neighbor = <<TNN:16, 0, 0, 0, 0, 0>>,
						metric = erlang:trunc(random:uniform() * 1000),
						sub_tlv = []}
				     end, TNLinks)
		      },
		NL = #isis_lsp{
			lsp_id = NLSPID,
			last_update = isis_protocol:current_timestamp(),
			pdu_type = level1_lsp,
			remaining_lifetime = 500,
			sequence_number = State#state.sequence,
			partition = false,
			overload = false,
			isis_type = level_1_2,
			tlv = [#isis_tlv_area_address{areas = isis_system:areas()},
			       #isis_tlv_protocols_supported{protocols = [ipv4]},
			       #isis_tlv_dynamic_hostname{hostname = NHostname},
			       NReachabilityTLV,
			       #isis_tlv_extended_ip_reachability{
				  reachability = [#isis_tlv_extended_ip_reachability_detail{
						     prefix = NPrefix,
						     mask_len = 24,
						     metric = 1,
						     up = true,
						     sub_tlv = []}]}
			      ]
		       },
		NCSum = isis_protocol:checksum(NL),
		[NL#isis_lsp{checksum = NCSum}] ++ LSPs;
	    false ->
		LSPs
	end,
    
    %% Now create the coffee/deadbeef node
    CDLSPID = <<Link:6/binary, 0, 0>>,
    CDHostname = case Link of
		     <<16#c0, 16#ff, 16#fe, 0, 0, 0>> -> "coffee";
		     _ -> "deadbeef"
		 end,
    CDReachabilityTLV = 
	#isis_tlv_extended_reachability{
	   reachability = 
	       lists:map(fun(N) ->
				 #isis_tlv_extended_reachability_detail{
				    neighbor = <<N:16, 0, 0, 0, 0, 0>>,
				    metric = erlang:trunc(random:uniform() * 1000),
				    sub_tlv = []}
			 end, Nodes)
	   ++ [#isis_tlv_extended_reachability_detail{
		  neighbor = <<(isis_system:system_id()):6/binary, 0>>,
		  metric = erlang:trunc(random:uniform() * 1000),
		  sub_tlv = []}]
	  },
    CDL = #isis_lsp{
	     lsp_id = CDLSPID,
	     last_update = isis_protocol:current_timestamp(),
	     pdu_type = level1_lsp,
	     remaining_lifetime = 500,
	     sequence_number = State#state.sequence,
	     partition = false,
	     overload = false,
	     isis_type = level_1_2,
	     tlv = [#isis_tlv_area_address{areas = isis_system:areas()},
		    #isis_tlv_protocols_supported{protocols = [ipv4]},
		    #isis_tlv_dynamic_hostname{hostname = CDHostname},
		    CDReachabilityTLV
		   ]
	    },
    CDSum = isis_protocol:checksum(CDL),
    CDLsp = CDL#isis_lsp{checksum = CDSum},
    LA = [CDLsp] ++ LSPs2,
    lists:map(fun(L) -> isis_lspdb:store_lsp(level_1, L) end,
	      LA).
	
random_list(Count) ->
     L = lists:seq(1,Count),
    [X||{_,X} <- lists:sort([ {random:uniform(), N} || N <- L])].
