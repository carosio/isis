%%%-------------------------------------------------------------------
%%% @author Rick Payne <rickp@rossfell.co.uk>
%%% @copyright (C) 2014, Rick Payne
%%% @doc
%%%
%%% @end
%%% Created :  3 Jan 2014 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------
-module(isis_debug).

-include("isis_protocol.hrl").

-define(ETH_P_802_2, 16#0400).

-define(TEST_INVALID_LSP,
  <<16#83, 16#1B>>).
-define(TEST_VALID_LSP,
  <<16#83,16#1B,16#01,16#00,16#14,16#01,16#00,16#00,
    16#00,16#8F,16#04,16#AE,16#FF,16#FF,16#00,16#00,
    16#00,16#03,16#00,16#00,16#00,16#00,16#00,16#12,
    16#96,16#DE,16#03,16#01,16#04,16#03,16#49,16#00,
    16#02,16#81,16#02,16#CC,16#8E,16#86,16#04,16#AC,
    16#10,16#44,16#02,16#84,16#04,16#AC,16#10,16#44,
    16#02,16#89,16#05,16#4F,16#6C,16#69,16#76,16#65,
    16#80,16#18,16#0A,16#80,16#80,16#80,16#AC,16#10,
    16#44,16#00,16#FF,16#FF,16#FF,16#00,16#0A,16#80,
    16#80,16#80,16#C0,16#A8,16#F7,16#00,16#FF,16#FF,
    16#FF,16#00,16#87,16#10,16#00,16#00,16#00,16#0A,
    16#18,16#AC,16#10,16#44,16#00,16#00,16#00,16#0A,
    16#18,16#C0,16#A8,16#F7,16#02,16#0C,16#00,16#0A,
    16#80,16#80,16#80,16#FF,16#FF,16#00,16#00,16#00,
    16#02,16#01,16#16,16#1B,16#FF,16#FF,16#00,16#00,
    16#00,16#02,16#01,16#00,16#00,16#0A,16#10,16#06,
    16#04,16#AC,16#10,16#44,16#02,16#04,16#08,16#00,
    16#00,16#00,16#43,16#00,16#00,16#00,16#00>>).
-define(TEST_VALID_CSNP,
<<131,33,1,0,25,1,0,0,0,83,255,255,0,0,0,2,0,0,0,0,0,0,0,0,0,255,255,255,255,
  255,255,255,255,9,48,4,90,255,255,0,0,0,2,0,0,0,0,0,28,240,47,4,170,255,255,
  0,0,0,2,1,0,0,0,0,22,113,65,2,11,255,255,0,0,0,3,0,0,0,0,0,16,154,220>>).

-define(TEST_VALID_IIH,
<<131,27,1,0,16,1,0,0,2,255,255,0,0,0,2,0,30,5,217,64,255,255,0,0,0,2,1,1,4,3,
  73,0,1,129,1,204,132,4,192,168,247,141,6,6,0,12,41,85,31,22,211,1,0,8,255,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,8,255,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,8,255,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,8,255,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,8,255,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,8,157,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0>>).

%% API
-compile(export_all).

%%%===================================================================
%%% API
%%%===================================================================
valid_iih() ->
    ?TEST_VALID_IIH.

valid_lsp() ->
    ?TEST_VALID_LSP.

valid_csnp() ->
    ?TEST_VALID_CSNP.

invalid_lsp() ->
    ?TEST_INVALID_LSP.

%% Generate a chunk of LSPs into our LSPDB to test things So we create
%% a list of 'Count' numbers, and then turn each one into an LSP that
%% has 'reachability' to the previous and next LSP. ie. a long chain.
%% We give them a hostname as well. Then we inject into the Database..
inject_some_lsps(Level, Count, Seq)
  when Count < 50 ->
    isis_system:add_sid_addresses(<<1:16, 0, 0, 0, 0>>, [3232298895]),
    Numbers = lists:seq(1, Count),
    PDU = case Level of
	      level_1 -> level1_lsp;
	      _ -> level2_lsp
	  end,
    Creator = 
	fun(N, Acc) ->
		NeighborID = <<N:16, 0, 0, 0, 0, 0>>,
		NextNeighborID = <<(N+1):16, 0, 0, 0, 0, 0>>,
		LSPID = <<NeighborID/binary, 0>>,
		Hostname = string:concat("injected", integer_to_list(N)),
		PrefixBin = <<1:8, N:8, 0:16>>,
		<<Prefix:32>> = PrefixBin,
		L = #isis_lsp{
		       lsp_id = LSPID,
		       last_update = isis_protocol:current_timestamp(),
		       pdu_type = PDU,
		       remaining_lifetime = 500,
		       sequence_number = Seq,
		       partition = false,
		       overload = false,
		       isis_type = level_1_2,
		       tlv = [#isis_tlv_area_address{areas = isis_system:areas()},
			      #isis_tlv_protocols_supported{protocols = [ipv4]},
			      #isis_tlv_dynamic_hostname{hostname = Hostname},
			      #isis_tlv_extended_reachability{
				 reachability = [#isis_tlv_extended_reachability_detail{
						    neighbor = Acc,
						    metric = N,
						    sub_tlv = []},
						#isis_tlv_extended_reachability_detail{
						   neighbor = NextNeighborID,
						   metric = N,
						   sub_tlv = []
						  }
						]},
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
		%% isis_lspdb:store(level_2, L#isis_lsp{checksum = CSum}),
		{L#isis_lsp{checksum = CSum}, NeighborID}
	end,
    Start = <<(isis_system:system_id()):6/binary, 0>>,
    {LSPs, _} = lists:mapfoldl(Creator, Start, Numbers),
    %% Now inject into the database
    Injector = 	fun(L) -> isis_lspdb:store_lsp(Level, L) end,
    lists:map(Injector, LSPs),
    ChainTLV = #isis_tlv_extended_reachability{
		  reachability = [#isis_tlv_extended_reachability_detail{
				     neighbor = <<1:16, 0, 0, 0, 0, 0>>,
				     metric = 10, sub_tlv=[]}]},
    isis_system:update_tlv(ChainTLV, 0, Level),
    ok;
inject_some_lsps(_, _, _) ->
    error.


purge_injected_lsps(Level, Count) ->
    IDCreator = fun(N) -> <<N:16, 0, 0, 0, 0, 0, 0>> end,
    LSPIDs = lists:map(IDCreator, lists:seq(1, Count)),
    Purge = fun(LSPID) -> isis_lspdb:purge_lsp(Level, LSPID) end,
    lists:map(Purge, LSPIDs),
    ChainTLV = #isis_tlv_extended_reachability{
		  reachability = [#isis_tlv_extended_reachability_detail{
				     neighbor = <<1:16, 0, 0, 0, 0, 0>>,
				     metric = 10, sub_tlv=[]}]},
    isis_system:delete_tlv(ChainTLV, 0, Level),
    isis_system:delete_sid_address(<<1:16, 0, 0, 0, 0>>, [3232298895]),
    ok.

debug_socket(Ifindex) ->
    {ok, Ref} = inert:start(),
    {ok, S} = procket:open(0, [{progname, "sudo /usr/local/bin/procket"},
			       {family, packet},
			       {type, raw},
			       {protocol, ?ETH_P_802_2}]),
    Family = procket:family(packet),
    LL = <<Family:16/native, ?ETH_P_802_2:16/native, Ifindex:32/native,
	   0:16, 0:8, 0:8, 0:8/unit:8>>,
    io:format("LL size: ~p (~p)~n", [byte_size(LL), LL]),
    ok = procket:bind(S, LL),
    %% run_socket(Ref, S).
    erlang:open_port({fd, S, S}, [binary, stream]).

run_socket(Ref, S) ->
    inert:poll(Ref, S, [{mode, read}]),
    case procket:recvfrom(S, 2048) of
	{ok, <<_R:17/binary, PDU/binary>>} ->
	    io:format("Received: ~p~n", [isis_protocol:decode(PDU)]),
	    
	    run_socket(Ref, S);
	_ -> error
    end.

%%%===================================================================
%%% Internal functions
%%%===================================================================
