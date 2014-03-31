%%%-------------------------------------------------------------------
%%% @author Rick Payne <rickp@rossfell.co.uk>
%%% @copyright (C) 2014, Rick Payne
%%% @doc
%%%
%%% spf_feed provides a feed of the output of the SPF run so we can
%%% use it to generate the graph in a webpage.
%%%
%%% @end
%%% Created : 18 Jan 2014 by Rick Payne <rickp@rossfell.co.uk>
%%%-------------------------------------------------------------------
-module(spf_feed).

-include ("../deps/yaws/include/yaws_api.hrl").

-export([out/1, handle_message/1, terminate/2]).

-export([handle_call/3, handle_info/2, handle_cast/2, code_change/3]).

out(A) ->
    
  case get_upgrade_header(A#arg.headers) of
    undefined ->
	  
	  {content, "text/plain", "You are not a websocket, Go away!"};
          "websocket" ->      Opts = [
          {keepalive,         true},
          {keepalive_timeout, 10000}
         ],
      {websocket, www_nmea, Opts};
    Any ->
      error_logger:error_msg("Got ~p from the upgrade header!", [Any])
  end.

handle_message({text, <<"start">>}) ->
    spf_summary:subscribe(self()),
    noreply;

handle_message({close, Status, _Reason}) ->
    {close, Status};

handle_message(Any) ->
    error_logger:error_msg("Received ~p", [Any]),
    noreply.

terminate(_Reason, _State) ->
    spf_summary:unsubscribe(self()),
    ok.

%% handle_info({nmea_summary, Message}, _State) ->
%%     Json = json2:encode({struct, Message}),
%%     {reply, {text, list_to_binary(Json)}};

%% Gen Server functions
handle_info(Info, State) ->
    error_logger:info_msg("~p unknown info msg ~p", [self(), Info]),
    {noreply, State}.

handle_cast(Msg, State) ->
    error_logger:info_msg("~p unknown msg ~p", [self(), Msg]),
    {noreply, State}.

handle_call(Request, _From, State) ->
    error_logger:info_msg("~p unknown call ~p", [self(), Request]),
    {stop, {unknown_call, Request}, State}.

code_change(_OldVsn, Data, _Extra) ->
    {ok, Data}.

get_upgrade_header(#headers{other=L}) ->
    lists:foldl(fun({http_header,_,K0,_,V}, undefined) ->
                        K = case is_atom(K0) of
                                true ->
                                    atom_to_list(K0);
                                false ->
                                    K0
                            end,
                        case string:to_lower(K) of
                            "upgrade" ->
                                string:to_lower(V);
                            _ ->
                                undefined
                        end;
                   (_, Acc) ->
                        Acc
                end, undefined, L).
