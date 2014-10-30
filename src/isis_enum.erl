%%%-------------------------------------------------------------------
%%% @author Rick Payne <rickp@rossfell.co.uk>
%%% @copyright (C) 2014, Alistair Woodman, California USA <awoodman@netdef.org>
%%% @doc
%%% Define the TLVs used for our IS-IS implementation.
%%% Note, these are parse-transformed to provide a set of functions isis_tlv:to_atom
%%% and isis_tlv:to_int which take the enum type and convert in either direction.
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
%%% Created :  2 Jan 2014 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------
-module(isis_enum).
-author('Rick Payne <rickp@rossfell.co.uk>').

%%% Note that these will throw bad_atom on failure,
%%% but there is no way to describe this in 'spec'
%%% Ignore flymake errors, as these functions are parse-transformed
-spec to_atom(atom(), integer()) -> atom().
-spec to_int(atom(), atom()) -> integer().

%%%
%%% PDU types, the ones that we actually use and understand
%%%
-enum({pdu, [{pdu_type_unset, 0},   %% Make typer happy
	     {level1_iih, 15},
	     {level2_iih, 16},
	     {p2p_iih, 17},
	     {level1_lsp, 18},
	     {level2_lsp, 20},
	     {level1_csnp, 24},
	     {level2_csnp, 25},
	     {level1_psnp, 26},
	     {level2_psnp, 27}]}).

%%%
%%% ISType - isis system type
%%%
-enum({istype, [{error, 0},
		{level_1, 1},
		{level_2, 2},      %% Invalid value really...
		{level_1_2, 3}]}).

%%%
%%% TLV types used in PDUs - its an 8bit field, but there are some
%%% Sub-TLVs that are per-TLV
%%%
-enum({tlv, [{unknown, 0},
	     {area_address, 1},
	     {is_reachability, 2},
	     {is_neighbors, 6},
	     {padding, 8},
	     {lsp_entry, 9},
	     {authentication, 10},
	     {checksum, 12},
	     {extended_reachability, 22},
	     {is_alias, 24},
	     {ip_internal_reachability, 128},
	     {protocols_supported, 129},
	     {ip_external_reachability, 130},
	     {idrp_information, 131},
	     {ip_interface_address, 132},
	     {te_router_id, 134},
	     {extended_ip_reachability, 135},
	     {dynamic_hostname, 137},
	     {slrg, 138},
	     {restart, 211},
	     {mt_is_reachability, 222},
	     {mt_supported, 229},
	     {ipv6_interface_address, 232},
	     {ipv6_reachability, 236},
	     {mt_ipv6_reachability, 237},
	     {p2p_adjacency_state, 240},
	     {iih_sequence_number, 241},
	     {vendor_proprietary, 250},
	     %%% when we get teh codepoint for this, we should change
	     %%% it...
	     {hardware_fingerprint, 254}
	    ]}).

%%%
%%% Sub TLVs
%%%
-enum({subtlv_is_reachability,
       [{admin_group, 3},
	{link_local_ri, 4},
	{link_remote_ri, 5},
	{ipv4_interface_address, 6},
	{ipv4_neighbor_address, 8},
	{max_link_bandwidth, 9},
	{reservable_link_bandwidth, 10},
	{unreserved_bandwidth, 11},
	{traffic_engineering_metric, 18},
	{link_protection_type, 20},
	{interface_switching_capability, 21}
	]}).

-enum({subtlv_eir,
       [{admin_tag_32bit, 1},
	{admin_tag_64bit, 2}
	]}).

-enum({subtlv_eis,
       [{unknown, 0},
	{admin_group, 3},
	{link_id, 4},
	{link_remote_id, 5},
	{ipv4_interface, 6},
	{ipv4_neighbor, 8},
	{max_bandwitdh, 9},
	{reservable_bandwidth, 10},
	{unreservable_bandwidth, 11},
	{te_metric, 18},
	{link_protection, 20},
	{interface_switching, 21}
	]}).

-enum({subtlv_ipv6r,
       [{unknown, 0},
	{source_prefix, 255}      %% Not IANA defined yet!
       ]}).

%%%
%%% Other defines that are used in IS-IS
%%%
-enum({protocols,
       [{null, 0},
	{ipv6, 16#8e},
	{ipv4, 16#cc}
       ]}).

-enum({metric_type,
       [{internal, 0},
	{external, 1}
       ]}).

-enum({authentication_type,
       [{unknown, 0},
	{text, 1},
	{md5, 17}]}).

-enum({boolean,
       [{false, 0},
	{true, 1}
       ]}).
