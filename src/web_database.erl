-module(web_database).

-include_lib("xmerl/include/xmerl.hrl").
-include("isis_protocol.hrl").

-export([init/3, handle/2, terminate/3]).

init(_Type, Req, _Opts) ->
    {ok, Req, no_state}.

handle(Req, State) ->
    {ok, XML} = get_document(),
    {ok, Req2} = cowboy_req:reply(200,
        [
            {<<"content-type">>, <<"text/html">>}
        ], erlang:list_to_binary(XML), Req),
    {ok, Req2, State}.

terminate(_Reason, _Req, _State) ->
    ok.

% Internal

text(Name, Content) ->
    #xmlElement{name = Name, content = [
        #xmlText{value = lists:flatten(Content)}
    ]}.

dump_lsp(LSP) ->
    <<ID:6/binary, PN:8, Frag:8>> = LSP#isis_lsp.lsp_id,
    Now = isis_protocol:current_timestamp(),
    RL = LSP#isis_lsp.remaining_lifetime - (Now - LSP#isis_lsp.last_update),
    SIDBin = lists:flatten(io_lib:format("~4.16.0B.~4.16.0B.~4.16.0B",
					 [X || <<X:16>> <= ID])),
    LSPStr = lists:flatten(io_lib:format("~s.~2.16.0B-~2.16.0B (~s)",
					 [isis_system:lookup_name(ID), PN, Frag, SIDBin])),
    TLVs =
	lists:foldl(
	  fun({A, B}, Acc) ->
		  Tail = case io_lib:printable_list(B) of
		      true -> [#xmlElement{name=tr, content=[
				  text(td, A), text(td, B)
			      ]}];
		      _ -> lists:map(fun(C) ->
					 #xmlElement{name=tr, content=[
					     text(td, A), text(td, C)
					 ]}
				     end, B)
		  end,
                  Acc ++ Tail
	  end, [],
	  lists:map(fun isis_protocol:pp_tlv/1, LSP#isis_lsp.tlv)),
    [ #xmlElement{name=table, attributes=[#xmlAttribute{name=width,
                                                        value="100%"}],
                  content=[
         #xmlElement{name=tr, attributes=[#xmlAttribute{name=style,
                                                       value="font-weight: bold"}],
                     content=[
             text(td, LSPStr),
             text(td, io_lib:format("0x~8.16.0B", [LSP#isis_lsp.sequence_number])),
             text(td, io_lib:format("~B", [RL]))
         ]}
     ]},
     #xmlElement{name=table, attributes=[#xmlAttribute{name=width,
                                                      value="100%"}],
                 content=TLVs},
     #xmlElement{name=hr}
    ].

get_database() ->
    LSPs = ets:tab2list(isis_lspdb:get_db(level_1)),
    lists:foldl(fun(LSP,Acc) -> Acc ++ dump_lsp(LSP) end, [], LSPs).

get_document() ->
    Root = #xmlElement{
        name = 'html',
        content = [
            #xmlElement{
               name = 'head',
               content = [
                   #xmlElement{
                      name = meta,
                      attributes = [ #xmlAttribute{name=charset,
                                                   value="utf-8"} ]
                   },
                   text(title, web_title:get_title()),
                   text(style, "body {\n"
                            ++ "        background-color: #dddddd;\n"
                            ++ "        font-color: #111111;\n"
                            ++ "}\n"
                            ++ "tr:hover {\n"
                            ++ "        background-color: #eeeeff;\n"
                            ++ "}")
               ]
            },
            #xmlElement{
               name = 'body',
               content = [
                   #xmlElement{
                      name = 'div',
                      attributes = [ #xmlAttribute{name=class,
                                                   value="database"} ],
                      content = get_database()
                   }
               ]
            }
        ]
    },
    {ok, xmerl:export([Root], xmerl_xml)}.
