"""Light liquid-glass presentation; no changes to analysis or stored data."""

import streamlit as st

CSS = """
<style>
:root {color-scheme:light;--rd-ink:#152443;--rd-muted:#526582;--rd-edge:rgba(255,255,255,.88);--rd-shadow:0 8px 30px rgba(64,106,151,.09)}
.stApp {color:var(--rd-ink);background:radial-gradient(ellipse at 75% 12%,#d9faf6aa,transparent 48%),radial-gradient(ellipse at 12% 65%,#dce3ffb0,transparent 48%),linear-gradient(135deg,#e1effb,#f2f8ff 52%,#e4f5fb);background-attachment:fixed}
/* Transparent header must not intercept clicks on the dataset picker. */
[data-testid="stHeader"] {background:transparent;pointer-events:none}
[data-testid="stHeader"] * {pointer-events:none!important}
[data-testid="stHeader"] button,[data-testid="stHeader"] button *,[data-testid="stHeader"] a,[data-testid="stHeader"] a * {pointer-events:auto!important}
[data-testid="stSidebar"] {width:240px!important;min-width:240px!important;margin:18px 0 18px 18px;height:calc(100% - 36px);border:1px solid var(--rd-edge);border-radius:28px;background:rgba(255,255,255,.38);backdrop-filter:blur(24px);box-shadow:var(--rd-shadow)}
[data-testid="stMainBlockContainer"] {max-width:1600px;padding:1.25rem 2rem 3rem 2.5rem}
[data-testid="stSidebarUserContent"] {padding-top:1rem}
[data-testid="stSidebar"] [role="radiogroup"] label {width:100%}
[data-testid="stSidebar"] [role="radiogroup"] label p:before {content:"";display:inline-block;width:24px;height:24px;margin-right:15px;vertical-align:middle;background-size:contain;background-repeat:no-repeat}
[data-testid="stSidebar"] [role="radiogroup"]>div:nth-child(1) label p:before {background-image:url("data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjMjQ0NzZiIiBzdHJva2Utd2lkdGg9IjEuNyIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIj48cGF0aCBkPSJtMyAxMCA5LTcgOSA3djEwSDdWMTBtMyAxMHYtN2g0djciLz48L3N2Zz4=")}
[data-testid="stSidebar"] [role="radiogroup"]>div:nth-child(2) label p:before {background-image:url("data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjMjQ0NzZiIiBzdHJva2Utd2lkdGg9IjEuNyIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIj48ZWxsaXBzZSBjeD0iMTIiIGN5PSI1IiByeD0iOCIgcnk9IjMiLz48cGF0aCBkPSJNNCA1djE0YzAgNCAxNiA0IDE2IDBWNU00IDEyYzAgNCAxNiA0IDE2IDAiLz48L3N2Zz4=")}
[data-testid="stSidebar"] [role="radiogroup"]>div:nth-child(3) label p:before {background-image:url("data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjMjQ0NzZiIiBzdHJva2Utd2lkdGg9IjEuNyIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIj48cGF0aCBkPSJNNiAzaDlsNCA0djE0SDZ6TTE0IDN2NWg1TTkgMTJoN005IDE2aDciLz48L3N2Zz4=")}
[data-testid="stSidebar"] [role="radiogroup"]>div:nth-child(4) label p:before {background-image:url("data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjMjQ0NzZiIiBzdHJva2Utd2lkdGg9IjEuNyIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIj48cGF0aCBkPSJNNCAyMFYxMmg0djh6bTYgMFY0aDR2MTZ6bTYgMFY4aDR2MTJ6Ii8+PC9zdmc+")}
[data-testid="stSidebar"] [role="radiogroup"]>div:nth-child(5) label p:before {background-image:url("data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjMjQ0NzZiIiBzdHJva2Utd2lkdGg9IjEuNyIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIj48cGF0aCBkPSJNNiAzaDlsNCA0djE0SDZ6TTkgMTd2LTRtNCA0VjltNCA4di02Ii8+PC9zdmc+")}

h1,h2,h3 {color:#111d38!important;font-weight:650!important;letter-spacing:-.025em}
h1 {font-size:2.6rem!important} h2 {font-size:1.4rem!important} h3 {font-size:1.15rem!important}
[data-testid="stCaptionContainer"] {color:var(--rd-muted)}
[data-testid="stMetric"], .st-key-rd_graph_panel, .st-key-rd_ranking_panel, .st-key-rd_ai_panel {background:linear-gradient(135deg,rgba(255,255,255,.76),rgba(255,255,255,.40));border:1px solid var(--rd-edge)!important;border-radius:24px!important;box-shadow:var(--rd-shadow),inset 0 1px 0 #fff;backdrop-filter:blur(18px)}
[data-testid="stMetric"] {padding:1.1rem 1.2rem;min-height:116px;position:relative}
[data-testid="stMetricLabel"],[data-testid="stMetricValue"] {margin-left:55px}
[data-testid="stMetric"]:before {content:"";position:absolute;left:14px;top:24px;width:43px;height:50px;border-radius:14px;background:linear-gradient(135deg,#c4ecff,#d5f1ff);border:1px solid white;box-shadow:0 3px 10px #add7e533}
[data-testid="stMetricValue"] {font-weight:650;font-size:2rem;color:#152443}
[data-testid="stMetricLabel"] p {white-space:normal!important}
.st-key-rd_graph_panel,.st-key-rd_ranking_panel {padding:1.2rem}
.st-key-rd_graph_mode [role="radiogroup"] {display:flex;gap:0;border:1px solid white;border-radius:24px;background:#ffffff66;padding:4px;width:fit-content}
.st-key-rd_graph_mode label {padding:7px 15px;border-radius:20px}
.st-key-rd_graph_mode label:has(input:checked) {background:#c7faf1;box-shadow:0 2px 8px #81cfce33}
.st-key-rd_graph_mode [data-testid="stRadioOption"]>div>div:first-child {display:none}
[data-testid="stSidebar"] [role="radiogroup"] {gap:.6rem}
[data-testid="stSidebar"] [role="radiogroup"] label {padding:.85rem .9rem;border-radius:19px;border:1px solid transparent}
[data-testid="stSidebar"] [role="radiogroup"] label:has(input:checked) {background:linear-gradient(120deg,#e2fffa,#aef0ee88);color:#086d79;border-color:#fff;box-shadow:0 3px 14px #78d8de44,inset 0 1px 0 white}
[data-testid="stSidebar"] [data-testid="stRadioOption"]>div>div:first-child {display:none}
[data-testid="stSidebar"] [role="radiogroup"] label p {font-size:1rem}
[data-testid="stButton"] button, [data-testid="stDownloadButton"] button, [data-testid="stFormSubmitButton"] button {border-radius:16px;border:1px solid #b6dfe4;background:rgba(255,255,255,.65);color:#067987;box-shadow:0 3px 10px #77a7c211;transition:background .15s}
[data-testid="stButton"] button:hover {background:#dcfffa;border-color:#61c7cf}
button[kind="primary"], [data-testid="stBaseButton-primary"], [data-testid="stBaseButton-primaryFormSubmit"] {background:linear-gradient(135deg,#087f8b,#18b8b8);border-color:#8aeeeb;color:#fff}
[data-baseweb="select"]>div, [data-baseweb="input"], [data-baseweb="textarea"] {background:rgba(255,255,255,.76)!important;border-color:#d5e4ef!important;border-radius:14px!important;color:#152443}
[data-testid="stExpander"] {background:rgba(255,255,255,.42);border-radius:16px;border-color:#d7e6ef}
[data-testid="stGraphVizChart"] {border-radius:20px}
[data-testid="stDataFrame"] {border-radius:16px;overflow:hidden}
.rd-brand {text-align:center;font-size:1.4rem;font-weight:700;margin:0 0 1.2rem;letter-spacing:-.04em}
.rd-brand span {display:block;width:64px;margin:0 auto 10px;padding:3px 0;font-size:2.6rem;color:#087e98;background:linear-gradient(135deg,#ffffffd9,#c2eafa88);border:1px solid white;border-radius:20px;box-shadow:0 6px 16px #91bed744}
.rd-kicker {font-size:.7rem;letter-spacing:.13em;text-transform:uppercase;color:#617892;margin-bottom:.3rem}
.rd-source {display:inline-block;font-size:.76rem;border-radius:20px;padding:5px 12px;background:#e0f7f4b3;color:#087582;border:1px solid #fff}
.rd-path {padding:15px;border-radius:15px;background:#e6f7f5b0;font-size:.95rem;margin:8px 0;overflow-wrap:anywhere}
.st-key-rd_ai_panel {padding:1.2rem;min-height:560px}
.st-key-rd_ai_panel h3:before {content:"✦";display:inline-block;margin-right:12px;color:#079ab2;background:#c7f1ff;border-radius:50%;width:32px;text-align:center}
.st-key-rd_ai_toggle button {background:linear-gradient(135deg,#efffff,#9feff3);border:2px solid white;border-radius:30px;box-shadow:0 3px 15px #66cddd55;color:#075b72;font-weight:650}
.rd-finding {display:inline-block;padding:5px 11px;background:#ffe0e5;border:1px solid #ffbec8;border-radius:9px;color:#b32e48;font-weight:650}
.rd-engine-note {padding:16px;border-radius:18px;background:#ffffff99;border:1px solid white;line-height:1.65;margin-bottom:1rem}
@media(max-width:1100px){[data-testid="stHorizontalBlock"]:has(> [data-testid="stColumn"] .st-key-rd_ai_panel){flex-wrap:wrap}[data-testid="stHorizontalBlock"]:has(> [data-testid="stColumn"] .st-key-rd_ai_panel)>[data-testid="stColumn"]{width:100%!important;flex:1 1 100%!important;min-width:0!important}}
@media(max-width:740px){[data-testid="stMainBlockContainer"]{padding:1rem}[data-testid="stSidebar"]{margin:0;border-radius:0;height:100%}h1{font-size:1.7rem!important}}
@media(prefers-reduced-transparency:reduce){[data-testid="stSidebar"],.st-key-rd_ai_panel,[data-testid="stMetric"]{background:#f4f9ff;backdrop-filter:none}}
[data-testid="stHorizontalBlock"]>[data-testid="stColumn"]:nth-child(1) [data-testid="stMetric"]:before {background-image:url("data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjMTI3YTk5IiBzdHJva2Utd2lkdGg9IjEuOCIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIj48cGF0aCBkPSJtMTIgMyA5IDUtOSA1LTktNXptLTkgOSA5IDUgOS01TTMgMTZsOSA1IDktNSIvPjwvc3ZnPg=="),linear-gradient(135deg,#d4f6ff,#e7f0ff);background-size:27px 27px,100% 100%;background-repeat:no-repeat;background-position:center}
[data-testid="stHorizontalBlock"]>[data-testid="stColumn"]:nth-child(2) [data-testid="stMetric"]:before {background-image:url("data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjMTI3YTk5IiBzdHJva2Utd2lkdGg9IjEuOCIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIj48cGF0aCBkPSJtMTIgMyA4IDN2NmMwIDUtOCA5LTggOXMtOC00LTgtOVY2eiIvPjwvc3ZnPg=="),linear-gradient(135deg,#d4f6ff,#e7f0ff);background-size:27px 27px,100% 100%;background-repeat:no-repeat;background-position:center}
[data-testid="stHorizontalBlock"]>[data-testid="stColumn"]:nth-child(3) [data-testid="stMetric"]:before {background-image:url("data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjMTI3YTk5IiBzdHJva2Utd2lkdGg9IjEuOCIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIj48Y2lyY2xlIGN4PSIxMiIgY3k9IjQiIHI9IjIiLz48Y2lyY2xlIGN4PSI1IiBjeT0iMjAiIHI9IjIiLz48Y2lyY2xlIGN4PSIxOSIgY3k9IjIwIiByPSIyIi8+PHBhdGggZD0iTTEyIDZ2NUg1djdtNy03aDd2NyIvPjwvc3ZnPg=="),linear-gradient(135deg,#d4f6ff,#e7f0ff);background-size:27px 27px,100% 100%;background-repeat:no-repeat;background-position:center}
[data-testid="stHorizontalBlock"]>[data-testid="stColumn"]:nth-child(4) [data-testid="stMetric"]:before {background-image:url("data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjMTI3YTk5IiBzdHJva2Utd2lkdGg9IjEuOCIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIj48Y2lyY2xlIGN4PSIxMiIgY3k9IjEyIiByPSI5Ii8+PHBhdGggZD0ibTEyIDEyIDUtNE03IDE3aDEwIi8+PC9zdmc+"),linear-gradient(135deg,#d4f6ff,#e7f0ff);background-size:27px 27px,100% 100%;background-repeat:no-repeat;background-position:center}
.st-key-rd_scope_bar {max-width:300px;margin-bottom:1rem}
[data-testid="stMainBlockContainer"] {padding-top:1rem}
.st-key-rd_scope_bar {margin-bottom:.25rem}
.st-key-rd_ai_panel [data-testid="stButton"] button {border-radius:24px;text-align:left;font-size:.85rem}
[data-testid="stHorizontalBlock"]>[data-testid="stColumn"]:nth-child(2) [data-testid="stMetric"]:before {background-color:#ffe0e6}
[data-testid="stHorizontalBlock"]>[data-testid="stColumn"]:nth-child(3) [data-testid="stMetric"]:before {background-color:#e4dcff}
[data-testid="stHorizontalBlock"]>[data-testid="stColumn"]:nth-child(4) [data-testid="stMetric"]:before {background-color:#c9f6ef}
/* Round only finding-label backgrounds; never touch arrowheads or asset nodes. */
[data-testid="stGraphVizChart"] svg g.edge polygon[fill="#ffe4e7"] {
    clip-path:inset(0 round 999px);
}
.rd-glass-graph {width:100%;overflow-x:auto;padding:0 2px 8px}
.rd-glass-graph>svg {display:block;width:100%;min-width:640px;height:auto;max-height:420px;font-family:Arial,sans-serif}
.st-key-rd_graph_panel {padding:1.15rem 1.3rem!important}
.st-key-rd_graph_panel [data-testid="stCaptionContainer"] {font-size:.7rem}
.st-key-rd_graph_panel [data-testid="stExpander"] {margin-top:0;background:#ffffff44}
.st-key-rd_ranking_panel [data-testid="stVerticalBlock"][class*="_row_"] {border-top:1px solid #dce7f3;padding:.7rem 0}
.rd-severity {display:inline-block;padding:4px 12px;border-radius:20px;background:#ffe1e6;color:#ba344b;font-size:.8rem}
.st-key-rd_graph_mode [data-testid="stWidgetLabel"] {display:none}
.rd-brand {margin-bottom:1.3rem}
[data-testid="stSidebarUserContent"] {padding-top:0!important}
[data-testid="stSidebar"] [role="radiogroup"] label {padding:.8rem .7rem}
.st-key-rd_graph_panel,.st-key-rd_ranking_panel {background:linear-gradient(115deg,#ffffffb8,#f9fcff80 55%,#dffaf940)!important}
[data-testid="stMainBlockContainer"] {padding-top:1.2rem}
</style>
"""


def apply_theme():
    st.html(CSS)
