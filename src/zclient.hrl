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

-define (ZEBRA_HEADER_MARKER, 255).
-define (ZEBRA_HEADER_SIZE, 6).
-define (ZSERV_VERSION, 2).

-define (ZEBRA_AFI_IPV4, 2).
-define (ZEBRA_AFI_IPV6, 10).

%%%===================================================================
%%% Messages
%%%===================================================================
-record (zclient_header, {
	   command :: atom(),
	   length :: integer()
	  }).
-type zclient_header() :: #zclient_header{}.
