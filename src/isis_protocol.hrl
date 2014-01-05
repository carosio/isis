%%%-------------------------------------------------------------------
%%% @author Rick Payne <rickp@rossfell.co.uk>
%%% @copyright (C) 2014, Rick Payne
%%% @doc
%%%
%%% @end
%%% Created :  2 Jan 2014 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------

-define(ISIS_MIN_MSG_SIZE, 27).

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

-record (isis_tlv_ip_interface_address, {
	   addresses :: [integer()]}).
-type isis_tlv_ip_interface_address() :: #isis_tlv_ip_interface_address{}.

-record (isis_tlv_protocols_supported, {
	   protocols :: [atom()]}).
-type isis_tlv_protocols_supported() :: #isis_tlv_protocols_supported{}.

-type isis_tlv() ::
	isis_tlv_area_address() |
	isis_tlv_dynamic_hostname() |
	isis_tlv_ip_interface_address() |
	isis_tlv_protocols_supported() |
	isis_tlv_unknown().

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

-record(isis_header, {
	  discriminator = 16#83 :: integer(),
	  header_length :: integer(),
	  version = 16#01 :: integer(),
          id_length = 16#06 :: integer(),
	  pdu_type :: atom(),
	  pdu_version :: integer(),
	  maximum_areas :: integer()
}).
-type isis_header() :: #isis_header{}.

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

-record(isis_lsp, {
	  version :: integer(),
	  pdu_type :: atom(),                  %% L1 or L2 LSP
	  remaining_lifetime :: integer(),
	  lsp_id :: binary(),
	  sequence_number :: integer(),
	  tlv :: [isis_tlv()]
	 }).
-type isis_lsp() :: #isis_lsp{}.

-record(isis_csnp, {
	  pdu_type :: atom(),
	  source_id :: binary(),
	  start_lsp_id :: binary(),
	  end_lsp_id :: binary(),
	  tlv :: [isis_tlv()]
	 }).
-type isis_csnp() :: #isis_csnp{}.


-type isis_pdu() ::
	isis_lsp() |
	isis_csnp().
