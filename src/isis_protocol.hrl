%%%-------------------------------------------------------------------
%%% @author Rick Payne <rickp@rossfell.co.uk>
%%% @copyright (C) 2014, Rick Payne
%%% @doc
%%%
%%% @end
%%% Created :  2 Jan 2014 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------

-define(ISIS_MIN_MSG_SIZE, 27).

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

-record (isis_tlv_is_reachability_detail, {
	   neighbor :: binary(),
	   default :: isis_metric_information(),
	   delay :: isis_metric_information(),
	   expense :: isis_metric_information(),
	   error :: isis_metric_information()
	  }).
-type isis_tlv_is_reachability_detail() :: #isis_tlv_is_reachability_detail{}.
-record (isis_tlv_is_reachability, {
	   virtual :: atom(),
	   is_reachability :: [isis_tlv_is_reachability_detail()]}).
-type isis_tlv_is_reachability() :: #isis_tlv_is_reachability{}.

-record (isis_tlv_padding, {
	   size :: integer()}).
-type isis_tlv_padding() :: #isis_tlv_padding{}.

-record (isis_tlv_lsp_entry_detail, {
	   lifetime :: integer(),
	   lsp_id :: binary(),
	   sequence :: integer(),
	   checksum :: integer()}).
-type isis_tlv_lsp_entry_detail() :: #isis_tlv_lsp_entry_detail{}.
-record (isis_tlv_lsp_entry, {
	   lsps :: [isis_tlv_lsp_entry_detail()]}).
-type isis_tlv_lsp_entry() :: #isis_tlv_lsp_entry{}.

-record (isis_tlv_dynamic_hostname, {
	   hostname :: nonempty_string()}).
-type isis_tlv_dynamic_hostname() :: #isis_tlv_dynamic_hostname{}.

-record (isis_metric_information, {
	   metric_supported :: atom(),
	   metric :: integer(),
	   metric_type :: atom()
	  }).
-type isis_metric_information() :: #isis_metric_information{}.

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
	   sub_tlv :: [isis_subtlv_eis()]}).
-type isis_tlv_extended_reachability_detail() :: #isis_tlv_extended_reachability_detail{}.
	   
-record (isis_tlv_extended_reachability, {
	   reachability :: [isis_tlv_extended_reachability_detail()]}).
-type isis_tlv_extended_reachability() :: #isis_tlv_extended_reachability{}.

-record (isis_tlv_ip_interface_address, {
	   addresses :: [integer()]}).
-type isis_tlv_ip_interface_address() :: #isis_tlv_ip_interface_address{}.

-record (isis_tlv_protocols_supported, {
	   protocols :: [atom()]}).
-type isis_tlv_protocols_supported() :: #isis_tlv_protocols_supported{}.

-record (isis_tlv_te_router_id, {
	   router_id :: integer()}).
-type isis_tlv_te_router_id() :: #isis_tlv_te_router_id{}.

-type isis_tlv() ::
	isis_tlv_area_address() |
	isis_tlv_is_reachability() |
	isis_tlv_padding() |
	isis_tlv_lsp_entry() |
	isis_tlv_dynamic_hostname() |
	isis_tlv_ip_interface_address() |
	isis_tlv_ip_internal_reachability() |
	isis_tlv_extended_ip_reachability() |
	isis_tlv_extended_reachability() |
	isis_tlv_protocols_supported() |
	isis_tlv_te_router_id() |
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

-record (isis_subtlv_eis_unknown, {
	   type :: integer(),
	   value :: binary()}).
-type isis_subtlv_eis_unknown() :: #isis_subtlv_eis_unknown{}.

-type isis_subtlv_eis() ::
	isis_subtlv_eis_link_id() |
	isis_subtlv_eis_ipv4_interface() |
	isis_subtlv_eis_unknown().

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
	   version :: integer(),
	   pdu_type :: atom(),                  %% L1 or L2 LSP
	   remaining_lifetime :: integer(),
	   lsp_id :: binary(),
	   sequence_number :: integer(),
	   checksum :: integer(),
	   partition :: atom(),
	   overload :: atom(),
	   isis_type :: atom(),
	   tlv :: [isis_tlv()]
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
	isis_lsp() |
	isis_csnp() |
	isis_psnp().
