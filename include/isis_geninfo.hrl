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
%%% Created :  18 Nov 2014 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------

-define(GENINFO_REFRESH_TIME, 1 * 1000).
-define(GENINFO_JITTER, 25).

-record(isis_geninfo_frag, {
	  remaining_size = 255,
	  tlvs = [] :: list(),
	  updated = false :: true | false,
	  previous_encode = <<>> :: binary()
	 }).

-record(isis_geninfo_client, {
	  level = level_1,
	  app,
	  ip = undefined,
	  frags = [#isis_geninfo_frag{}],
	  add_func,         %%
	  delete_func,      %% 
	  encode_func,      %% Encode a TLV type fir this client into bytes
	  decode_func,      %% Decodes bytes into a typed struct (understood by the client
	  mergetype_func    %% For a given TLV returns add or replace or array
	 }).
