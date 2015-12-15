%%%-------------------------------------------------------------------
%%% @author Christian Franke <chris@opensourcerouting.org>
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
%%% Created : 18 December 2014 by Christian Franke <chris@opensourcerouting.org
%%%-------------------------------------------------------------------

-record (spf_ext_info, {
	    id,
	    spf_type,
	    delayed,
	    scheduled,
	    started,
	    ended,
	    trigger_lsp = []
}).
