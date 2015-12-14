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
%%% Created :  2 Jan 2014 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------

-define(ISIS_MIN_MSG_SIZE, 27).
-define(ISIS_HELLO_JITTER, 25).
-define(ISIS_LSP_JITTER, 25).
-define(ISIS_PSNP_JITTER, 25).
-define(ISIS_CSNP_JITTER, 25).

-define(DEFAULT_HOLD_TIME, 10 * 1000).
-define(ISIS_PSNP_TIMER, 10 * 1000).
-define(ISIS_CSNP_TIMER, 10 * 1000).
-define(ISIS_P2P_CSNP_TIMER, 60 * 1000).
-define(ISIS_CSNP_PACE_TIMER, 0.25 * 1000).
-define(ISIS_SPF_DELAY, 4). %% 4ms
-define(ISIS_IIH_IPV6COUNT, 15).

-define(ISIS_MAX_LSP_LIFETIME, 1200).
-define(ISIS_LSP_REFRESH_DELAY, 2000).
-define(DEFAULT_EXPIRY_TIMER, 60).
-define(DEFAULT_LSP_AGEOUT, 300).
-define(DEFAULT_SPF_DELAY, 0.01).   %% 100ms
-define(DEFAULT_AGEOUT_CHECK, 27).
-define(DEFAULT_METRIC, 100).
-define(DEFAULT_AUTOCONF_METRIC, 1000000).
-define(DEFAULT_PRIORITY, 64).

%% We default to 'normal' L2 IS-IS
-define(DEFAULT_INTERFACE_MODULE, isis_interface_l2).

-define(LSP_ENTRY_DETAIL_PER_TLV, 15).   %% 15 LSP_ENTY_DETAIL records per LSP_ENTRY TLV
-define(LSP_ENTRY_PER_PDU, 6).           %% 6 LSP_ENTRY objects per PDU

%% This isn't very pretty, but it sure calms down dialyzer on fun2ms() stuff...
-type matchspec_atom() :: '_' | '$1' | '$2' | '$3' | '$4' | '$5' | '$6' | '$7' | '$8' | '$9'.

%%%===================================================================
%%% Used to create the LSPs we generate
%%%===================================================================
-record(lsp_frag, {level :: atom(),        %% Level
		   pseudonode = 256 :: 0..255,   %% Pseudo-node
		   fragment = 0 :: 0..255, %% Fragment
		   sequence = 1 :: integer(),  %% Sequence number
		   updated  = false :: atom(),      %% Do we need to refresh this LSP?
		   size = ?ISIS_MIN_MSG_SIZE :: integer(),      %% Packet size so far
		   tlvs = [] :: [isis_tlv()]}).
-type lsp_frag() :: #lsp_frag{}.

%%%===================================================================
%%% TLV records
%%%===================================================================
-record (isis_tlv_unknown, {
	   type :: integer(),
	   bytes :: binary()}).
-type isis_tlv_unknown() :: #isis_tlv_unknown{}.

-record (isis_tlv_area_address, {
	   areas :: [binary()]}).
-type isis_tlv_area_address() :: #isis_tlv_area_address{}.

-record (isis_metric_information, {
	   metric_supported  = false:: atom(),
	   metric = 0 :: integer(),
	   metric_type = internal :: atom()
	  }).
-type isis_metric_information() :: #isis_metric_information{}.

-record (isis_tlv_is_reachability_detail, {
	   neighbor :: binary(),
	   default = #isis_metric_information{} :: isis_metric_information(),
	   delay = #isis_metric_information{} :: isis_metric_information(),
	   expense = #isis_metric_information{} :: isis_metric_information(),
	   error = #isis_metric_information{} :: isis_metric_information()
	  }).
-type isis_tlv_is_reachability_detail() :: #isis_tlv_is_reachability_detail{}.
-record (isis_tlv_is_reachability, {
	   virtual :: atom(),
	   is_reachability :: [isis_tlv_is_reachability_detail()]}).
-type isis_tlv_is_reachability() :: #isis_tlv_is_reachability{}.

-record (isis_tlv_is_neighbors, {
	   neighbors :: [binary()]}).
-type isis_tlv_is_neighbors() :: #isis_tlv_is_neighbors{}.

-record (isis_tlv_padding, {
	   size :: integer()}).
-type isis_tlv_padding() :: #isis_tlv_padding{}.

-record (isis_tlv_lsp_entry_detail, {
	   lsp_id = <<>> :: binary(),
	   lifetime = 0 :: integer(),
	   sequence = 0 :: integer(),
	   checksum = 0 :: integer()}).
-type isis_tlv_lsp_entry_detail() :: #isis_tlv_lsp_entry_detail{}.
-record (isis_tlv_lsp_entry, {
	   lsps :: [isis_tlv_lsp_entry_detail()]}).
-type isis_tlv_lsp_entry() :: #isis_tlv_lsp_entry{}.

-record (isis_tlv_authentication, {
	   type :: atom(),
	   signature :: binary(),
	   do_not_rewrite  = true :: boolean()}).
-type isis_tlv_authentication() :: #isis_tlv_authentication{}.

-record (isis_tlv_dynamic_hostname, {
	   hostname :: nonempty_string()}).
-type isis_tlv_dynamic_hostname() :: #isis_tlv_dynamic_hostname{}.

-record (isis_tlv_ip_internal_reachability_detail, {
	   ip_address :: integer(),
	   subnet_mask :: integer(),
	   default :: isis_metric_information(),
	   delay :: isis_metric_information(),
	   expense :: isis_metric_information(),
	   error :: isis_metric_information()
	  }).
-type isis_tlv_ip_internal_reachability_detail() :: #isis_tlv_ip_internal_reachability_detail{}.
-record (isis_tlv_ip_internal_reachability, {
	   ip_reachability :: [isis_tlv_ip_internal_reachability_detail()]}).
-type isis_tlv_ip_internal_reachability() :: #isis_tlv_ip_internal_reachability{}.

-record (isis_tlv_extended_ip_reachability_detail, {
	   prefix :: integer(),
	   mask_len :: integer(),
	   metric :: integer(),
	   up :: atom(),
	   sub_tlv :: [isis_subtlv_eir()]}).
-type isis_tlv_extended_ip_reachability_detail() :: #isis_tlv_extended_ip_reachability_detail{}.

-record (isis_tlv_extended_ip_reachability, {
	   reachability :: [isis_tlv_extended_ip_reachability_detail()]}).
-type isis_tlv_extended_ip_reachability() :: #isis_tlv_extended_ip_reachability{}.

-record (isis_tlv_extended_reachability_detail, {
	   neighbor :: binary(),
	   metric :: integer(),
	   sub_tlv = [] :: [isis_subtlv_eis()]}).
-type isis_tlv_extended_reachability_detail() :: #isis_tlv_extended_reachability_detail{}.
	   
-record (isis_tlv_extended_reachability, {
	   reachability :: [isis_tlv_extended_reachability_detail()]}).
-type isis_tlv_extended_reachability() :: #isis_tlv_extended_reachability{}.

-record (isis_tlv_ip_interface_address, {
	   addresses :: [integer()]}).
-type isis_tlv_ip_interface_address() :: #isis_tlv_ip_interface_address{}.

-record (isis_tlv_ipv6_interface_address, {
	   addresses :: [binary()]}).
-type isis_tlv_ipv6_interface_address() :: #isis_tlv_ipv6_interface_address{}.

-record (isis_subtlv_srcdst, {
	   prefix_length :: integer(),
	   prefix :: binary()
	  }).
-type isis_subtlv_srcdst() :: #isis_subtlv_srcdst{}.

-type isis_subtlv_ipv6r() ::
	isis_subtlv_srcdst() |
	isis_subtlv_unknown().

-record (isis_tlv_ipv6_reachability_detail, {
	   metric :: integer(),
	   up :: boolean(),
	   external :: boolean(),
	   mask_len :: integer(),
	   prefix :: binary(),
	   sub_tlv = [] :: [isis_subtlv_ipv6r()]}).
-type isis_tlv_ipv6_reachability_detail() :: #isis_tlv_ipv6_reachability_detail{}.

-record (isis_tlv_ipv6_reachability, {
	   reachability = [] :: [isis_tlv_ipv6_reachability_detail]
	  }).
-type isis_tlv_ipv6_reachability() :: #isis_tlv_ipv6_reachability{}.

-record (isis_tlv_protocols_supported, {
	   protocols :: [atom()]}).
-type isis_tlv_protocols_supported() :: #isis_tlv_protocols_supported{}.

-record (isis_tlv_te_router_id, {
	   router_id :: integer()}).
-type isis_tlv_te_router_id() :: #isis_tlv_te_router_id{}.

-record (isis_tlv_restart, {
	   request :: boolean(),
	   acknowledge :: boolean(),
	   supress_adjacency :: boolean(),
	   remaining :: integer(),
	   neighbor :: binary()}).
-type isis_tlv_restart() :: #isis_tlv_restart{}.

-record (isis_tlv_geninfo, {
	   d_bit = false :: boolean(),
	   s_bit = false :: boolean(),
	   application_id :: integer(),
	   application_ip_address = undefined :: undefined | tuple(), %% #isis_address{}
	   application_gunk :: binary()}).
-type isis_tlv_geninfo() :: #isis_tlv_geninfo{}.

-record (isis_tlv_hardware_fingerprint, {
	   fingerprint :: binary()}).
-type isis_tlv_hardware_fingerprint() :: #isis_tlv_hardware_fingerprint{}.

-record (isis_tlv_p2p_adjacency_state, {
	   state :: atom(),
	   local_circuit :: integer(),
	   neighbor :: binary(),
	   neighbor_circuit :: integer()}).
-type isis_tlv_p2p_adjacency_state() :: #isis_tlv_p2p_adjacency_state{}.

-type isis_tlv() ::
	isis_tlv_area_address() |
	isis_tlv_is_reachability() |
	isis_tlv_is_neighbors() |
	isis_tlv_padding() |
	isis_tlv_lsp_entry() |
	isis_tlv_authentication() |
	isis_tlv_dynamic_hostname() |
	isis_tlv_ip_interface_address() |
	isis_tlv_ipv6_interface_address() |
	isis_tlv_ipv6_reachability() |
	isis_tlv_ip_internal_reachability() |
	isis_tlv_extended_ip_reachability() |
	isis_tlv_extended_reachability() |
	isis_tlv_protocols_supported() |
	isis_tlv_te_router_id() |
	isis_tlv_restart() |
	isis_tlv_geninfo() |
	isis_tlv_hardware_fingerprint() |
	isis_tlv_p2p_adjacency_state() |
	isis_tlv_unknown().

%%%===================================================================
%%% Sub TLV records
%%%===================================================================
%%% Extended IP Reachability SubTLVs
-record (isis_subtlv_eir_admintag32, {
	   tag :: integer()}).
-type isis_subtlv_eir_admintag32() :: #isis_subtlv_eir_admintag32{}.
-record (isis_subtlv_eir_admintag64, {
	   tag :: integer()}).
-type isis_subtlv_eir_admintag64() :: #isis_subtlv_eir_admintag64{}.

-type isis_subtlv_eir() ::
	isis_subtlv_eir_admintag32() |
	isis_subtlv_eir_admintag64().

%%% Extended IS reachability SubTLVs
-record (isis_subtlv_eis_link_id, {
	   local :: integer(),
	   remote :: integer()}).
-type isis_subtlv_eis_link_id() :: #isis_subtlv_eis_link_id{}.

-record (isis_subtlv_eis_ipv4_interface, {
	   address :: integer()}).
-type isis_subtlv_eis_ipv4_interface() :: #isis_subtlv_eis_ipv4_interface{}.

-record (isis_subtlv_eis_unify_interface, {
	   name :: list()}).
-type isis_subtlv_eis_unify_interface() :: #isis_subtlv_eis_unify_interface{}.

-record (isis_subtlv_unknown, {
	   type :: integer(),
	   value :: binary()}).
-type isis_subtlv_unknown() :: #isis_subtlv_unknown{}.

-type isis_subtlv_eis() ::
	isis_subtlv_eis_link_id() |
	isis_subtlv_eis_ipv4_interface() |
	isis_subtlv_eis_unify_interface() |
	isis_subtlv_unknown().

%%%-------------------------------------------------------------------
%%% IS-IS raw packet format
%%% 
%%% Destination MAC           6 bytes
%%% Source MAC                6 bytes
%%% 802.3 Length Field        2 bytes
%%% 802.3 DSAP -    16#FE     1 byte
%%% 802.3 SSAP -    16#FE     1 byte
%%% 802.3 Control - 16#03     1 byte
%%% IS-IS Common Header etc   27 bytes - MTU-4
%%% FCS                       4 bytes
%%%-------------------------------------------------------------------

-record (isis_header, {
	   discriminator = 16#83 :: integer(),
	   header_length :: integer(),
	   version = 16#01 :: integer(),
	   id_length = 16#06 :: integer(),
	   pdu_type :: atom(),
	   pdu_version :: integer(),
	   maximum_areas :: integer()
	  }).
-type isis_header() :: #isis_header{}.

-record (isis_iih, {
	   circuit_type :: atom(),
	   pdu_type :: atom(),                  %% L1 or L2
	   source_id :: binary(),
	   holding_time :: integer(),
	   priority :: integer(),
	   dis :: binary(),
	   tlv :: [isis_tlv()]
	  }).
-type isis_iih() :: #isis_iih{}.

-record (isis_p2p_iih, {
	   circuit_type :: atom(),
	   pdu_type :: atom(),                  %% L1 or L2
	   source_id :: binary(),
	   holding_time :: integer(),
	   local_circuit_id :: integer(),
	   tlv :: [isis_tlv()]
	  }).
-type isis_p2p_iih() :: #isis_p2p_iih{}.

%%%-------------------------------------------------------------------
%%% IS-IS LSP
%%% 
%%% IS-IS Common Header etc   27 bytes
%%% PDU Length                2 bytes
%%% Remaining Lifetime        2 Bytes
%%% LSP-ID                    ID-Len (typically 6) + 2
%%% Sequence Number           4 bytes
%%% Checksum                  2 bytes
%%% Flags                     1 byte
%%% TLVs                      remaining bytes
%%%-------------------------------------------------------------------

-record (isis_lsp, {
	   lsp_id :: binary() | matchspec_atom(),        %% The key
	   id_length = 0 :: integer() | matchspec_atom(), %% ID Len as we received it
	   last_update :: integer() | matchspec_atom(),
	   version :: integer() | matchspec_atom(),
	   pdu_type :: atom() | matchspec_atom(),                  %% L1 or L2 LSP
	   remaining_lifetime = 0 :: integer() | matchspec_atom(),
	   sequence_number = 0 :: integer() | matchspec_atom(),
	   checksum = 0 :: integer() | matchspec_atom(),
	   partition = false :: atom() | matchspec_atom(),
	   overload = false :: atom() | matchspec_atom(),
	   isis_type  = level_1_2 :: atom() | matchspec_atom(),
	   tlv = []:: [isis_tlv()] | matchspec_atom()
	  }).
-type isis_lsp() :: #isis_lsp{}.

-record (isis_csnp, {
	   pdu_type :: atom(),
	   source_id :: binary(),
	   start_lsp_id :: binary(),
	   end_lsp_id :: binary(),
	   tlv :: [isis_tlv()]
	  }).
-type isis_csnp() :: #isis_csnp{}.

-record (isis_psnp, {
	   pdu_type :: atom(),
	   source_id :: binary(),
	   tlv :: [isis_tlv()]
	  }).
-type isis_psnp() :: #isis_psnp{}.

-type isis_pdu() ::
	isis_iih() |
	isis_p2p_iih() |
	isis_lsp() |
	isis_csnp() |
	isis_psnp().
