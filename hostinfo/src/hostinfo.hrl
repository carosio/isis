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
%%% Created : 6 Dec 2014 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------

-define(HOSTINFO_APPID, 16#0002).   %% Our ISIS GenInfo App ID
-define(HOSTINFO_REFRESH_TIME, (5 * 60 * 1000)).
-define(HOSTINFO_JITTER, 25).

%%%===================================================================
%%% Hostinfo TLV details
%%%===================================================================
-record (hostinfo_hostname, {
	   hostname :: nonempty_string()}).

-record (hostinfo_processor, {
	   processor :: nonempty_string()}).

-record (hostinfo_memused, {
	   memory_used :: integer()}).
