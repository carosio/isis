-module(web_state_netconf).

-export([init/3, handle/2, terminate/3]).

init (_Type, Req, _Opts) ->
    {ok, Req, no_state}.

handle(Req, State) ->
    {ok, XML} = isis_netconf:process_state({}),
    %% It would be really neat if we could easily generate
    %% indented XML. Not sure how to do that though.
    %% For now, just hoping a browser will indent for viewing
    %% and otherwise using "xmllint --format" on the output.
    {ok, Req2} = cowboy_req:reply(200,
        [
            {<<"content-type">>, <<"text/xml">>}
        ], erlang:list_to_binary(XML), Req),
    {ok, Req2, State}.

terminate(_Reason, _Req, _State) ->
    ok.
