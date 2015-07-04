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
%%% Created :  3 Jan 2014 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------
-module(isis_debug).

-include("isis_system.hrl").
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
inject_some_lsps(Level, Count, Seq) ->
    inject_some_lsps(Level, Count, Seq, false, false).
inject_some_lsps(Level, Count, Seq, Overload, Partition)
  when Count < 50 ->
    isis_system:add_sid_addresses(Level, <<1:16, 0, 0, 0, 0>>,  10, [{ipv4, {3232298895, 1, self()}}]),
    Numbers = lists:seq(1, Count),
    PDU = case Level of
	      level_1 -> level1_lsp;
	      _ -> level2_lsp
	  end,
    Creator = 
	fun(N, Acc) ->
		NeighborID = <<N:16, 0, 0, 0, 0, 0>>,
		NextNeighborID = <<(N+1):16, 0, 0, 0, 0, 0>>,
		NReachability = 
		    case N =:= Count of
			true ->
			    #isis_tlv_extended_reachability{
			       reachability = [#isis_tlv_extended_reachability_detail{
						  neighbor = Acc,
						  metric = N,
						  sub_tlv = []}
					      ]};
			_ ->
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
					      ]}
		    end,
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
		       partition = Partition,
		       overload = Overload,
		       isis_type = level_1_2,
		       tlv = [#isis_tlv_area_address{areas = isis_system:areas()},
			      #isis_tlv_protocols_supported{protocols = [ipv4]},
			      #isis_tlv_dynamic_hostname{hostname = Hostname},
			      NReachability,
			      #isis_tlv_extended_ip_reachability{
				 reachability = [#isis_tlv_extended_ip_reachability_detail{
						    prefix = Prefix,
						    mask_len = 24,
						    metric = 1,
						    up = true,
						    sub_tlv = []}]},
			      #isis_tlv_geninfo{application_id = 2,
						application_ip_address = undefined,
						application_gunk = <<1,4,"Fred",2,6,"x86_64">>},
			      #isis_tlv_unknown{type = 99, bytes = <<1,2,3,4,5,6,7,8,9,10>>}
			     ]
		      },
		CSum = isis_protocol:checksum(L),
		%% isis_lspdb:store(level_2, L#isis_lsp{checksum = CSum}),
		{L#isis_lsp{checksum = CSum}, NeighborID}
	end,
    Start = <<(isis_system:system_id()):6/binary, 0>>,
    {LSPs, _} = lists:mapfoldl(Creator, Start, Numbers),
    %% Now inject into the database
    Injector = 	fun(L) ->
			isis_lspdb:store_lsp(Level, L),
			isis_lspdb:flood_lsp(Level, isis_system:list_circuits(), L, none)
		end,
    lists:map(Injector, LSPs),
    ChainTLV = #isis_tlv_extended_reachability{
		  reachability = [#isis_tlv_extended_reachability_detail{
				     neighbor = <<1:16, 0, 0, 0, 0, 0>>,
				     metric = 16819, sub_tlv=[]}]},
    isis_system:update_tlv(ChainTLV, 0, Level, "eth1"),
    ok;
inject_some_lsps(_, _, _, _, _) ->
    error.

purge_injected_lsps(Level, Count) ->
    IDCreator = fun(N) -> <<N:16, 0, 0, 0, 0, 0, 0>> end,
    LSPIDs = lists:map(IDCreator, lists:seq(1, Count)),
    Purge = fun(LSPID) -> isis_lspdb:purge_lsp(Level, LSPID, none) end,
    lists:map(Purge, LSPIDs),
    ChainTLV = #isis_tlv_extended_reachability{
		  reachability = [#isis_tlv_extended_reachability_detail{
				     neighbor = <<1:16, 0, 0, 0, 0, 0>>,
				     metric = 10, sub_tlv=[]}]},
    isis_system:delete_tlv(ChainTLV, 0, Level, "eth1"),
    isis_system:delete_sid_addresses(Level, <<1:16, 0, 0, 0, 0>>, [{ipv4, {3232298895, 1, self()}}]),
    ok.

%% Expand a row and column count into a list of co-ords
expand_row_column(RowCount, ColumnCount) ->
    expand_row_column(lists:seq(1, RowCount), lists:seq(1, ColumnCount),
		      lists:seq(1, ColumnCount), []).

expand_row_column([], _, _Cols, Acc) ->
    %% Append our 'final' one as cheat...
    [{0, 0}] ++ lists:reverse([{16#FFFF, 16#FFFF} | Acc]);
expand_row_column([_H|T], [], Cols, Acc) ->
    expand_row_column(T, Cols, Cols, Acc);
expand_row_column([H|_T] = R, [A|B], Cols, Acc) ->
    expand_row_column(R, B, Cols, [{H, A} | Acc]).

pdu_type(level_1) -> level1_lsp;
pdu_type(level_2) -> level2_lsp.

%% For a given R, C which of the CoOrds list is our neighbor?
generate_neighbors(R, C, RMax, CMax, CoOrds) ->
    lists:filter(
      fun({_,1}) when R =:= 0, C =:= 0 -> true;
	 ({0, 0}) when C =:= 1 -> true;
	 ({A, B}) when A =:= R, B =:= C -> false;
	 ({A, B}) when A =:= R, B =:= (C-1) -> true;
	 ({A, B}) when A =:= R, B =:= (C+1) -> true;
	 %% ({A, B}) when C rem 2 =:= 1, A =:= (R-1), B =:= (C-1) -> true;
	 %% ({A, B}) when C rem 2 =:= 1, A =:= (R+1), B =:= (C-1) -> true;
	 %% ({A, B}) when C rem 2 =:= 0, A =:= (R-1), B =:= (C+1) -> true;
	 %% ({A, B}) when C rem 2 =:= 0, A =:= (R+1), B =:= (C+1) -> true;
	 ({A, B}) when C =:= CMax, A =:= 16#FFFF, B =:= 16#FFFF -> true;
	 ({_, B}) when R =:= 16#FFFF, C =:= 16#FFFF, B =:= CMax -> true;
	 ({_, _}) -> false
      end, CoOrds).

generate_node_id(0, 0) -> <<(isis_system:system_id()):6/binary, 0:8>>;
generate_node_id(R, C) -> <<R:16, C:16, 0:24>>.

generate_mesh_lsp(Level, 0, 0, CMax, RMax, CoOrds) ->
    %% 0,0 is code for 'ourself', so we take don't want to generate an
    %% LSP, we want to update our lsp.
    lists:map(fun({A, B}) ->
		      R = #isis_tlv_extended_reachability_detail{
			     neighbor = generate_node_id(A, B),
			     metric = crypto:rand_uniform(10, 100),
			     sub_tlv = []},
		      ChainTLV = #isis_tlv_extended_reachability{
				    reachability = [R]
				   },
		      isis_system:update_tlv(ChainTLV, 0, Level, "eth1")
	      end, generate_neighbors(0, 0, CMax, RMax, CoOrds)),
    false;
generate_mesh_lsp(Level, R, C, RMax, CMax, CoOrds) ->
    case C =:= 1 of
	true ->
	    <<N:6/binary, _:8>> = generate_node_id(R, C),
	    isis_system:add_sid_addresses(Level,
					  N, crypto:rand_uniform(10, 100),
					  [{ipv4, {3232298894 + R, 1, self()}}]);
	_ -> ok
    end,
    IPTLV =
	case {R, C} of
	    {16#FFFF, 16#FFFF} ->
		<<P:32>> = <<10:8, 1:8, 0:16>>,
		[#isis_tlv_extended_ip_reachability{
		   reachability = [#isis_tlv_extended_ip_reachability_detail{
				      prefix = P,
				      mask_len = 24,
				      metric = 1,
				      up = true,
				      sub_tlv = []}]}];
	    _ -> []
	end,
    PDU = pdu_type(Level),
    Reachability =
	lists:map(fun({A, B}) ->
			  #isis_tlv_extended_reachability_detail{
			     neighbor = generate_node_id(A, B),
			     metric = crypto:rand_uniform(10, 100),
			     sub_tlv = []}
		  end, generate_neighbors(R, C, RMax, CMax, CoOrds)),
    NeighborsTLV =
	 #isis_tlv_extended_reachability{
	    reachability = Reachability
	   },
    Hostname = lists:flatten(io_lib:format("injected-~2.10.0B-~2.10.0B", [R, C])),
    Seq =
	case isis_lspdb:lookup_lsps([<<(generate_node_id(R, C))/binary, 0:8>>], isis_lspdb:get_db(level_1)) of
	    [PreviousLSP] -> PreviousLSP#isis_lsp.sequence_number + 1;
	    _ -> 1
	end,
    {true,
     #isis_lsp{
	lsp_id = <<(generate_node_id(R, C))/binary, 0:8>>,
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
	      NeighborsTLV | IPTLV]
       }
    }.

inject_mesh(Level, Rows, Columns) ->
    %% Get the set of valid row/column address, plus 0,0 for ourselves and
    %% 16#FFFF, 16#FFFF for the final node...
    CoOrds = expand_row_column(Rows, Columns),
    LSPs =
	lists:filtermap(
	  fun({R, C}) -> generate_mesh_lsp(Level, R, C, Rows, Columns, CoOrds) end,
	  CoOrds),
    lists:map(
      fun(L) ->
	      isis_lspdb:store_lsp(Level, L),
	      isis_lspdb:flood_lsp(Level, isis_system:list_circuits(), L, none)
      end, LSPs).

%%%===================================================================
%%% Internal functions
%%%===================================================================
