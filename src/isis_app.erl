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
%%% Created :  2 Jan 2014 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------
-module(isis_app).
-author('Rick Payne <rickp@rossfell.co.uk>').

-behaviour(application).

%% Application callbacks
-export([start/2, stop/1]).

%%%===================================================================
%%% Application callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called whenever an application is started using
%% application:start/[1,2], and should start the processes of the
%% application. If the application is structured according to the OTP
%% design principles as a supervision tree, this means starting the
%% top supervisor of the tree.
%%
%% @spec start(StartType, StartArgs) -> {ok, Pid} |
%%                                      {ok, Pid, State} |
%%                                      {error, Reason}
%%      StartType = normal | {takeover, Node} | {failover, Node}
%%      StartArgs = term()
%% @end
%%--------------------------------------------------------------------
start(_StartType, _StartArgs) ->
    case isis_sup:start_link() of
	{ok, Pid} ->
	    {ok, Pid};
	Error ->
	    Error
		end.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called whenever an application has stopped. It
%% is intended to be the opposite of Module:start/2 and should do
%% any necessary cleaning up. The return value is ignored.
%%
%% @spec stop(State) -> void()
%% @end
%%--------------------------------------------------------------------
stop(_State) ->
    ok.

%%%===================================================================
%%% Internal functions
%%%===================================================================
