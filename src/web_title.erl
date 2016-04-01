-module(web_title).

-export([init/3, handle/2, terminate/3, get_title/0]).

init (_Type, Req, _Opts) ->
    {ok, Req, no_state}.

handle(Req, State) ->
    {ok, Req2} = cowboy_req:reply(200,
        [
            {<<"content-type">>, <<"text/plain">>}
        ], erlang:list_to_binary(get_title()), Req),
    {ok, Req2, State}.

terminate(_Reason, _Req, _State) ->
    ok.

get_title() ->
    <<A:16, B:16, C:16>> = isis_system:system_id(),
    io_lib:format("~s (~4.16.0B.~4.16.0B.~4.16.0B)",
                  [isis_system:get_state(hostname), A, B, C]).
