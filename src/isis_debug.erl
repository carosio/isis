%%%-------------------------------------------------------------------
%%% @author Rick Payne <rickp@rossfell.co.uk>
%%% @copyright (C) 2014, Alistair Woodman, California USA <awoodman@netdef.org>
%%% @doc
%%%
%%% This file is part of AutoISIS.
%%%
%%% License:
%%% AutoISIS can be used (at your option) under the following GPL or under
%%% a commercial license
%%% 
%%% Choice 1: GPL License
%%% AutoISIS is free software; you can redistribute it and/or modify it
%%% under the terms of the GNU General Public License as published by the
%%% Free Software Foundation; either version 2, or (at your option) any
%%% later version.
%%% 
%%% AutoISIS is distributed in the hope that it will be useful, but
%%% WITHOUT ANY WARRANTY; without even the implied warranty of
%%% MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See 
%%% the GNU General Public License for more details.
%%% 
%%% You should have received a copy of the GNU General Public License
%%% along with GNU Zebra; see the file COPYING.  If not, write to the Free
%%% Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
%%% 02111-1307, USA.
%%% 
%%% Choice 2: Commercial License Usage
%%% Licensees holding a valid commercial AutoISIS may use this file in 
%%% accordance with the commercial license agreement provided with the 
%%% Software or, alternatively, in accordance with the terms contained in 
%%% a written agreement between you and the Copyright Holder.  For
%%% licensing terms and conditions please contact us at 
%%% licensing@netdef.org
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
    isis_system:add_sid_addresses(<<1:16, 0, 0, 0, 0>>,  [{ipv4, 3232298895}]),
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
						    sub_tlv = []}]},
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
    Injector = 	fun(L) -> isis_lspdb:store_lsp(Level, L) end,
    lists:map(Injector, LSPs),
    ChainTLV = #isis_tlv_extended_reachability{
		  reachability = [#isis_tlv_extended_reachability_detail{
				     neighbor = <<1:16, 0, 0, 0, 0, 0>>,
				     metric = 16819, sub_tlv=[]}]},
    isis_system:update_tlv(ChainTLV, 0, Level),
    ok;
inject_some_lsps(_, _, _) ->
    error.


purge_injected_lsps(Level, Count) ->
    IDCreator = fun(N) -> <<N:16, 0, 0, 0, 0, 0, 0>> end,
    LSPIDs = lists:map(IDCreator, lists:seq(1, Count)),
    Purge = fun(LSPID) -> isis_system:purge_lsp(Level, LSPID) end,
    lists:map(Purge, LSPIDs),
    ChainTLV = #isis_tlv_extended_reachability{
		  reachability = [#isis_tlv_extended_reachability_detail{
				     neighbor = <<1:16, 0, 0, 0, 0, 0>>,
				     metric = 10, sub_tlv=[]}]},
    isis_system:delete_tlv(ChainTLV, 0, Level),
    isis_system:delete_sid_addresses(<<1:16, 0, 0, 0, 0>>, [{ipv4, 3232298895}]),
    ok.

%%%===================================================================
%%% Internal functions
%%%===================================================================
