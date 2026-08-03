package report

// page is the report template.
//
// Visual direction: cards on a tinted canvas, separated by elevation and space
// rather than a hairline around every element — the latter is what makes an
// interface read as a decade-old admin panel.
//
// Proportional type with tabular numerals throughout; monospace is reserved for
// machine identifiers, because setting everything in it makes a product look
// like a terminal dump. Colour is used as fill, never only as a 1px rule.
//
// The timeline is both the chart and the control. Drag across it and the
// inventory below filters to that window — the same gesture that reads the data
// selects it, so there is no separate filter UI to learn.
//
// No external references at all. Opens offline, from a USB stick, on a
// locked-down machine — which is often exactly where this work happens.
const page = `<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Network survey — {{.Source}}</title>
<style>
/* Dark is the default and the look the project leads with; light is one click
   away for printing and for attaching to an email.
   Separation comes from elevation and space, not from hairline borders around
   everything. Borders survive only where two things genuinely abut. */
:root{
  --bg:#F3F6FB; --surface:#FFF; --surface2:#F8FAFD; --raise:#F0F4FA;
  --rule:#E9EEF6; --rule2:#D6DEEA;
  --text:#0B1729; --dim:#5D6B85; --faint:#93A0B6;
  --sound:#2F6BFF; --soft:#EAF0FF; --ink:#E8590C;
  --crit:#E11D48; --high:#EA580C; --med:#CA8A04; --low:#64748B;
  --crit-bg:#FFF1F4; --high-bg:#FFF4EC; --med-bg:#FEFAEC; --low-bg:#F3F5F9;
  --glow:rgba(47,107,255,.12);
  --shadow:0 1px 2px rgba(11,23,41,.05),0 6px 16px -6px rgba(11,23,41,.09);
  --shadow-lg:0 2px 4px rgba(11,23,41,.05),0 14px 34px -12px rgba(11,23,41,.14);
  --c-server:#2F6BFF; --c-workstation:#6366F1; --c-printer:#8B5CF6;
  --c-camera:#F59E0B; --c-phone:#10B981; --c-mobile:#10B981;
  --c-nas:#0EA5E9; --c-plc:#F97316; --c-network:#06B6D4;
  --c-vm:#64748B; --c-iot:#EC4899; --c-unknown:#94A3B8;
}
html[data-theme="dark"]{
  --bg:#080D18; --surface:#111827; --surface2:#161F31; --raise:#1C2638;
  --rule:#22304A; --rule2:#30405D;
  --text:#EAF0F8; --dim:#94A6C0; --faint:#61738F;
  --sound:#5B8DFF; --soft:#16233F; --ink:#FB923C;
  --crit:#FB7185; --high:#FB923C; --med:#FACC15; --low:#8496AF;
  --crit-bg:#2A1620; --high-bg:#2A1D14; --med-bg:#26210F; --low-bg:#1A2131;
  --glow:rgba(91,141,255,.2);
  --shadow:0 1px 2px rgba(0,0,0,.4),0 6px 16px -6px rgba(0,0,0,.5);
  --shadow-lg:0 2px 4px rgba(0,0,0,.4),0 14px 34px -12px rgba(0,0,0,.6);
  --c-server:#5B8DFF; --c-workstation:#818CF8; --c-printer:#A78BFA;
  --c-camera:#FBBF24; --c-phone:#34D399; --c-mobile:#34D399;
  --c-nas:#38BDF8; --c-plc:#FB923C; --c-network:#22D3EE;
  --c-vm:#94A3B8; --c-iot:#F472B6; --c-unknown:#61738F;
}

*{box-sizing:border-box;margin:0;padding:0}
html{-webkit-text-size-adjust:100%}
body{
  background:var(--bg);color:var(--text);
  font:400 15px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  /* Tabular numerals everywhere: figures in a column must line up, and this is
     a document made almost entirely of figures. */
  font-variant-numeric:tabular-nums;
  padding-bottom:5rem;-webkit-font-smoothing:antialiased;
}
/* Monospace is reserved for machine identifiers — addresses, MACs, hashes.
   Using it for everything is what made the earlier draft read as a terminal
   dump rather than a product. */
.mono,code{font-family:ui-monospace,"SF Mono","Cascadia Mono","JetBrains Mono",Menlo,Consolas,monospace;
           font-size:.92em;letter-spacing:-.01em}
.wrap{max-width:1280px;margin:0 auto;padding:0 1.4rem}
.card{background:var(--surface);border-radius:12px;box-shadow:var(--shadow)}

/* ---- masthead ----------------------------------------------------------- */
header{padding:1.15rem 0 .2rem}
.title{display:flex;flex-wrap:wrap;align-items:center;gap:.5rem 1.4rem;margin-bottom:.9rem}
h1{font-size:1.02rem;font-weight:600;letter-spacing:-.01em;line-height:1;
   display:flex;align-items:center;gap:.5rem}
.wordmark{letter-spacing:-.015em}
h1 .of{color:var(--sound)}
.logo{width:22px;height:22px;color:var(--sound);flex:none}
.meta{margin-left:auto;text-align:right;font-size:.79rem;color:var(--faint);line-height:1.5}
.meta b{color:var(--dim);font-weight:500}

/* ---- headline figures --------------------------------------------------- */
.readout{display:grid;grid-template-columns:repeat(auto-fit,minmax(124px,1fr));gap:.6rem}
.stat{background:var(--surface);border-radius:12px;box-shadow:var(--shadow);padding:.85rem 1rem .9rem}
.stat .n{font-size:1.85rem;font-weight:650;line-height:1;letter-spacing:-.035em}
.stat .k{font-size:.76rem;color:var(--faint);margin-top:.34rem}
.stat.hot .n{color:var(--ink)}
.stat.good .n{color:var(--sound)}

/* ---- timeline ------------------------------------------------------------ */
.tl{margin-top:.6rem;background:var(--surface);border-radius:12px;box-shadow:var(--shadow);overflow:hidden}
.tl-head{display:flex;flex-wrap:wrap;align-items:center;gap:.5rem;padding:.7rem .95rem .55rem}
.tl-head .lbl{font-size:.82rem;font-weight:600}
.tl-head .sel{font-size:.79rem;color:var(--sound);margin-left:auto;font-weight:500}
.chips{display:flex;gap:.28rem;background:var(--raise);padding:.2rem;border-radius:9px}
.chip{font:inherit;font-size:.775rem;font-weight:500;background:transparent;color:var(--dim);
      border:0;padding:.3rem .68rem;border-radius:7px;cursor:pointer;white-space:nowrap;
      transition:background .14s,color .14s}
.chip:hover{color:var(--text);background:var(--surface)}
.chip[aria-pressed="true"],.chip[aria-expanded="true"]{background:var(--sound);color:#fff;
      box-shadow:0 1px 3px rgba(47,107,255,.35)}
.chip:focus-visible{outline:2px solid var(--sound);outline-offset:2px}
/* A preset longer than the capture is shown rather than removed: the row of
   ranges stays the same shape on every report, so the control does not appear
   to gain and lose buttons depending on how much data was scanned. */
.chip[disabled]{opacity:.34;cursor:default}
.chip[disabled]:hover{background:transparent;color:var(--dim)}

.plot{position:relative;height:78px;padding:.3rem .95rem .4rem;cursor:crosshair;
      user-select:none;touch-action:none}
.bars{position:relative;height:100%}
.bar{position:absolute;bottom:0;background:linear-gradient(180deg,var(--sound),var(--sound) 70%,
     color-mix(in srgb,var(--sound) 55%,transparent));opacity:.3;border-radius:2px 2px 0 0;
     transition:opacity .15s}
.bar.on{opacity:1}
.brush{position:absolute;top:-4px;bottom:-4px;background:var(--glow);border-radius:6px;
       pointer-events:none;display:none}
.axis{display:flex;justify-content:space-between;padding:0 .95rem .75rem;
      font-size:.74rem;color:var(--faint)}
.hint{color:var(--faint);font-size:.74rem}

/* ---- dashboard grid ------------------------------------------------------ */
/* Two columns above the fold: the inventory you browse, and the issues you act
   on. Each scrolls inside its own pane so neither pushes the other off screen. */
.grid{display:grid;grid-template-columns:minmax(0,1.55fr) minmax(310px,1fr);
      gap:.75rem;align-items:start;margin-top:.75rem}
@media (max-width:1080px){.grid{grid-template-columns:1fr}}

.pane{background:var(--surface);border-radius:12px;box-shadow:var(--shadow);
      display:flex;flex-direction:column;overflow:hidden}
.pane-head{display:flex;align-items:center;gap:.6rem;padding:.8rem .95rem .7rem;
           background:var(--surface);position:sticky;top:0;z-index:2;
           box-shadow:0 1px 0 var(--rule)}
.pane-head h2{font-size:.9rem;font-weight:600;letter-spacing:-.01em}
.pane-head .n{font-size:.79rem;color:var(--faint);margin-left:auto;white-space:nowrap}
.scroll{overflow-y:auto;overscroll-behavior:contain;max-height:min(60vh,660px)}
.scroll::-webkit-scrollbar{width:10px}
.scroll::-webkit-scrollbar-thumb{background:var(--rule2);border-radius:5px;
  border:3px solid var(--surface)}
.scroll::-webkit-scrollbar-track{background:transparent}

/* ---- findings ----------------------------------------------------------- */
/* Severity is a filled pill, not a coloured hairline. Colour as fill reads at a
   glance; colour as a 1px rule does not. */
.find{display:block;padding:.7rem .95rem .78rem;position:relative}
.find+.find{box-shadow:inset 0 1px 0 var(--rule)}
.find.critical{--sev:var(--crit);--sev-bg:var(--crit-bg)}
.find.high{--sev:var(--high);--sev-bg:var(--high-bg)}
.find.medium{--sev:var(--med);--sev-bg:var(--med-bg)}
.find.low,.find.info{--sev:var(--low);--sev-bg:var(--low-bg)}
.find .top{display:flex;align-items:center;gap:.5rem;margin-bottom:.3rem}
.find .sev{font-size:.665rem;font-weight:700;letter-spacing:.045em;color:var(--sev);
           background:var(--sev-bg);padding:.16rem .42rem;border-radius:5px;flex:none}
.find .addr{font-size:.74rem;color:var(--faint);margin-left:auto;flex:none}
.find .what{font-size:.885rem;font-weight:600;line-height:1.32;letter-spacing:-.005em}
.find .why{color:var(--dim);font-size:.8rem;margin-top:.22rem;line-height:1.45}
/* The fix is what makes this a task list rather than a list of complaints.
   It gets the accent colour and a rule of its own so the eye lands on it. */
.find .fix{font-size:.8rem;color:var(--dim);margin-top:.5rem;padding-left:.65rem;
           border-left:2px solid var(--sound);line-height:1.45}
.find .fix b{color:var(--sound);font-weight:600;margin-right:.3rem}
.find .cmd{position:relative;margin-top:.45rem;background:var(--raise);border-radius:7px;
           padding:.5rem 3.4rem .5rem .6rem;overflow-x:auto}
.find .cmd code{font-family:ui-monospace,"SF Mono",Menlo,Consolas,monospace;font-size:.715rem;
                color:var(--text);white-space:pre;display:block;line-height:1.55}
.copy{position:absolute;top:.36rem;right:.36rem;font:inherit;font-size:.66rem;font-weight:600;
      background:var(--surface);color:var(--dim);border:0;border-radius:5px;
      padding:.2rem .45rem;cursor:pointer;box-shadow:var(--shadow)}
.copy:hover{color:var(--sound)}
.copy:focus-visible{outline:2px solid var(--sound);outline-offset:1px}
.find .rep{font-size:.72rem;color:var(--faint);margin-top:.28rem}
.clear{padding:2.5rem 1rem;text-align:center;color:var(--dim);font-size:.88rem}
/* Findings the window is holding back are announced rather than dropped. A
   time filter that quietly removes a critical problem is worse than no filter,
   so the count stays visible and the way to see them is one click. */
.held{padding:.7rem .95rem;text-align:center;color:var(--dim);font-size:.79rem;
      box-shadow:0 -1px 0 var(--rule)}
.lnk{font:inherit;background:none;border:0;padding:0;color:var(--sound);
     cursor:pointer;text-decoration:underline}
.lnk:focus-visible{outline:2px solid var(--sound);outline-offset:2px;border-radius:3px}

/* ---- section headings (below the fold) ----------------------------------- */
.sec{display:flex;align-items:baseline;gap:1rem;margin:1.6rem 0 .8rem}
.sec h2{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.7rem;font-weight:600;
        letter-spacing:.18em;text-transform:uppercase}
.sec .rule{flex:1;height:1px;background:var(--rule)}
.sec .n{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.7rem;color:var(--faint)}

/* ---- inventory search ---------------------------------------------------- */
.search{flex:1;min-width:90px;max-width:230px;background:var(--bg);border:1px solid var(--rule);
        color:var(--text);padding:.24rem .55rem;border-radius:3px;font:inherit;font-size:.75rem}
.search::placeholder{color:var(--faint)}
.search:focus{outline:none;border-color:var(--sound)}

/* ---- dashboard panels ---------------------------------------------------- */
.panels{display:grid;grid-template-columns:repeat(auto-fit,minmax(215px,1fr));gap:.75rem;margin-top:.75rem}
.panel{background:var(--surface);border-radius:12px;box-shadow:var(--shadow);
       padding:.85rem .95rem .95rem;display:flex;flex-direction:column}
.panel h3{font-size:.85rem;font-weight:600;margin-bottom:.75rem;letter-spacing:-.005em}
.panel-foot{font-size:.73rem;color:var(--faint);margin-top:auto;padding-top:.5rem}

/* donut */
.ring{position:relative;width:92px;height:92px;margin:0 auto .75rem}
.ring svg{width:100%;height:100%;transform:rotate(-90deg)}
.ring circle{fill:none;stroke-width:5.5;stroke-linecap:round;transition:stroke-dasharray .35s}
.ring-c{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;
        justify-content:center;pointer-events:none}
.ring-c b{font-size:1.45rem;font-weight:650;line-height:1;letter-spacing:-.03em}
.ring-c span{font-size:.7rem;color:var(--faint);margin-top:.15rem}
.keys{list-style:none;display:flex;flex-wrap:wrap;gap:.18rem .8rem;font-size:.755rem;color:var(--dim)}
.keys i{display:inline-block;width:8px;height:8px;border-radius:3px;margin-right:.4rem}
.keys b{color:var(--text);font-weight:600}

/* horizontal bars */
.bars2{list-style:none;display:flex;flex-direction:column;gap:.55rem}
.bars2 li{display:grid;grid-template-columns:1fr auto;gap:.22rem .7rem;font-size:.775rem}
.bars2 .lb{color:var(--dim);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bars2 .vv{color:var(--text);font-weight:600}
.bars2 .tr{grid-column:1/-1;height:6px;background:var(--raise);border-radius:3px;overflow:hidden}
.bars2 .fi{height:100%;background:var(--c,var(--sound));border-radius:3px;transition:width .35s}

/* severity list */
.sevlist{list-style:none;display:flex;flex-direction:column;gap:.42rem}
.sevlist li{display:flex;align-items:center;gap:.55rem;font-size:.79rem;color:var(--dim)}
.sevlist .sq{width:10px;height:10px;border-radius:3px;flex:none}
.sevlist .ct{margin-left:auto;color:var(--text);font-weight:600}
.muted{color:var(--faint);font-size:.775rem;font-weight:400}

/* ---- device rows -------------------------------------------------------- */
.dev+.dev{box-shadow:inset 0 1px 0 var(--rule)}
.dev[open]{background:var(--surface2)}
.dev[hidden]{display:none}
.dev summary{display:grid;
  grid-template-columns:34px minmax(0,8.5rem) minmax(0,1fr) 5.5rem 2.6rem;
  gap:.8rem;align-items:center;padding:.46rem .95rem;cursor:pointer;list-style:none}
.dev summary::-webkit-details-marker{display:none}
.dev summary:hover{background:var(--raise)}
.dev summary:focus-visible{outline:2px solid var(--sound);outline-offset:-2px}

/* ---- SIGNATURE: the confidence ring -------------------------------------- */
/* The device's glyph sits inside an arc that fills to how sure we are that the
   glyph is right. Identity and certainty become one object — this report's one
   real claim is that it admits what it does not know, and this is where it says
   so, on every row, without a word. */
.ico{position:relative;width:34px;height:34px;display:grid;place-items:center;color:var(--c)}
.ico .ringc{position:absolute;inset:0;transform:rotate(-90deg)}
.ico .ringc circle{fill:none;stroke-width:2.2}
.ico .rbg{stroke:var(--rule)}
.ico .rfg{stroke:var(--c);stroke-linecap:round;transition:stroke-dasharray .4s}
.ico .glyph{width:16px;height:16px}
.dev[data-unk="1"] .ico .rfg{stroke:var(--faint)}

.addr-c{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.8rem;font-weight:500;
        display:flex;align-items:center;gap:.4rem;letter-spacing:-.01em}
.dot{width:6px;height:6px;border-radius:50%;flex:none}
.dot.critical{background:var(--crit)} .dot.high{background:var(--high)}
.dot.medium{background:var(--med)} .dot.low,.dot.info{background:var(--low)}
.host{font-size:.735rem;color:var(--faint);overflow:hidden;text-overflow:ellipsis;
      white-space:nowrap;margin-top:.06rem}
.ident{font-size:.845rem;font-weight:500;overflow:hidden;text-overflow:ellipsis;
       white-space:nowrap;line-height:1.3;letter-spacing:-.005em}
.ident.unk{color:var(--faint);font-weight:400}
.tags{font-size:.73rem;color:var(--dim);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tags .warn{color:var(--ink);font-weight:500}
.val{font-size:.755rem;color:var(--faint);text-align:right}
.sparkbox{position:relative;display:block;width:100%;height:20px}
.spark{width:100%;height:20px;overflow:visible;display:block}
.spark polyline{fill:none;stroke:var(--c);stroke-width:1.3;opacity:.85;
                stroke-linejoin:round;stroke-linecap:round;vector-effect:non-scaling-stroke}
/* Shows where the selected window sits within the device's whole history, so
   the trace stays readable as context instead of being cropped to the window. */
.sparksel{position:absolute;top:-2px;bottom:-2px;background:var(--glow);
          border-left:1px solid var(--sound);border-right:1px solid var(--sound);
          display:none;pointer-events:none}

/* ---- evidence ------------------------------------------------------------ */
.ev{padding:.9rem .95rem 1.1rem;box-shadow:inset 0 1px 0 var(--rule)}
.ev h3{font-size:.775rem;font-weight:600;color:var(--dim);margin-bottom:.6rem}
.facts{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));
       gap:.3rem 1.6rem;margin-bottom:1rem}
.fact{display:flex;gap:.65rem;font-size:.79rem}
.fact dt{color:var(--faint);min-width:4.8rem;flex:none}
.fact dd{color:var(--dim);word-break:break-word}
table{width:100%;border-collapse:collapse;font-size:.775rem}
th{text-align:left;font-weight:600;color:var(--faint);font-size:.735rem;
   padding:.3rem .8rem .35rem 0}
thead tr{box-shadow:inset 0 -1px 0 var(--rule)}
td{padding:.34rem .8rem;color:var(--dim);vertical-align:top;word-break:break-word;
   padding-left:0}
tbody tr+tr{box-shadow:inset 0 1px 0 var(--rule)}
td.w{color:var(--sound);text-align:right;white-space:nowrap;font-weight:500}
td.c{color:var(--text);font-weight:500}

/* ---- coverage ------------------------------------------------------------ */
.cov{display:grid;grid-template-columns:repeat(auto-fill,minmax(290px,1fr));gap:.15rem 1.5rem;
     background:var(--surface);border-radius:12px;box-shadow:var(--shadow);padding:.9rem 1rem}
.cv{display:grid;grid-template-columns:.7rem 4.2rem 1fr;gap:.55rem;align-items:baseline;
    font-size:.79rem;padding:.24rem 0}
.cv .dt{color:var(--sound);font-size:.7rem} .cv.off .dt{color:var(--faint)}
.cv .t{color:var(--text);font-weight:500;font-family:ui-monospace,Menlo,Consolas,monospace;
       font-size:.75rem}
.cv.off .t{color:var(--faint);font-weight:400}
.cv .d{color:var(--faint);font-size:.755rem} .cv.off .d{color:var(--ink)}
.note{background:var(--high-bg);border-radius:12px;padding:.9rem 1.1rem;margin-top:.75rem;
      font-size:.86rem;color:var(--dim);max-width:88ch;line-height:1.5}
.note b{color:var(--text)}
.empty{padding:2.5rem 1rem;text-align:center;color:var(--faint);font-size:.88rem}

footer{margin-top:2rem;padding-top:1.4rem;font-size:.775rem;color:var(--faint);line-height:1.65;
       box-shadow:inset 0 1px 0 var(--rule);text-align:center}
/* Wide enough that each sentence stays on its own line rather than wrapping
   into a four-line block. */
footer p{max-width:none;margin:0 auto}
footer .sig{margin-top:.9rem;display:flex;align-items:center;justify-content:center;gap:.45rem}
footer .sig svg{width:15px;height:15px;color:var(--sound)}
footer a{color:var(--sound);text-decoration:none;font-weight:500}
footer a:hover{text-decoration:underline}

.toggle{position:fixed;top:1rem;right:1rem;z-index:9;background:var(--surface);
        border:0;box-shadow:var(--shadow);color:var(--dim);width:34px;height:34px;
        border-radius:9px;cursor:pointer;font-size:.9rem;line-height:1}
.toggle:hover{color:var(--sound);box-shadow:var(--shadow-lg)}
.toggle:focus-visible{outline:2px solid var(--sound);outline-offset:2px}

@media (max-width:760px){
  .dev summary{grid-template-columns:1.3rem 1fr;gap:.3rem .7rem}
  .dev summary>:nth-child(n+3){grid-column:2}
  .meta{margin-left:0;text-align:left}
  .scroll{max-height:none}
}
@media print{
  .toggle,.chips,.search,.hint{display:none}
  body{background:#fff;color:#000;background-image:none}
  /* Panes scroll on screen; on paper everything must be present. */
  .scroll{max-height:none;overflow:visible}
  .grid{grid-template-columns:1fr}
  .dev,.find,.panel{break-inside:avoid}
  .dev[hidden]{display:none}
}
@media (prefers-reduced-motion:no-preference){
  .find{animation:rise .32s cubic-bezier(.2,.7,.3,1) backwards}
  .find:nth-child(2){animation-delay:.04s}.find:nth-child(3){animation-delay:.08s}
  .find:nth-child(4){animation-delay:.12s}.find:nth-child(5){animation-delay:.16s}
  @keyframes rise{from{opacity:0;transform:translateY(6px)}}
  .bar{animation:grow .5s cubic-bezier(.2,.8,.3,1) backwards}
  @keyframes grow{from{transform:scaleY(0)}}
}
.bar{transform-origin:bottom}
</style>
</head>
<body>
<button class="toggle" id="t" aria-label="Switch between light and dark">◐</button>

<header>
  <div class="wrap">
    <div class="title">
      <h1>
        <!-- Two enormous eyes. A tarsier finds everything by sitting perfectly
             still and watching; the mark says the whole product in one glance. -->
        <svg class="logo" viewBox="0 0 24 24" fill="none" stroke="currentColor"
             stroke-width="1.6" aria-hidden="true">
          <circle cx="8" cy="11" r="5.4"/>
          <circle cx="16" cy="11" r="5.4"/>
          <circle cx="9.4" cy="11" r="1.9" fill="currentColor" stroke="none"/>
          <circle cx="14.6" cy="11" r="1.9" fill="currentColor" stroke="none"/>
        </svg>
        <!-- One span, or the flex gap splits the wordmark into "Tar sier". -->
        <span class="wordmark">Tar<span class="of">sier</span></span></h1>
      <div class="meta">
        <div>Survey of <b>{{.Source}}</b></div>
        <div>{{.Generated}} · <b>{{comma .TotalEvents}}</b> events{{if .SpanLabel}} over {{.SpanLabel}}{{end}}</div>
      </div>
    </div>
  </div>
  <div class="wrap" style="padding-bottom:1.6rem">
    <div class="readout">
      <div class="stat good"><div class="n mono" id="s-dev">{{.CountDevices}}</div><div class="k">devices found</div></div>
      <div class="stat"><div class="n mono" id="s-ident">{{.CountIdentified}}</div><div class="k">identified</div></div>
      <div class="stat"><div class="n mono" id="s-named">{{.CountNamed}}</div><div class="k">named</div></div>
      <div class="stat{{if .CountFindings}} hot{{end}}"><div class="n mono" id="s-find">{{.CountFindings}}</div><div class="k">worth looking at</div></div>
      {{if .CountCritical}}<div class="stat hot" id="s-crit-card"><div class="n mono" id="s-crit">{{.CountCritical}}</div><div class="k">critical</div></div>{{end}}
    </div>

    {{if .HasTime}}
    <section class="tl">
      <div class="tl-head">
        <span class="lbl">Activity</span>
        <div class="chips" role="group" aria-label="Time range">
          <button class="chip" data-h="24">24 hours</button>
          <button class="chip" data-h="72">3 days</button>
          <button class="chip" data-h="168">7 days</button>
          <button class="chip" data-h="336">14 days</button>
          <button class="chip" data-h="720">30 days</button>
          <button class="chip" data-all="1">All</button>
        </div>
        <span class="hint">or drag the chart for any range</span>
        <span class="sel" id="sel">{{.FirstLabel}} — {{.LastLabel}}</span>
      </div>
      <div class="plot" id="plot">
        <div class="bars" id="bars">
          {{range .Timeline}}<div class="bar" style="left:{{.X}}%;width:{{.W}}%;height:{{.H}}%"
            data-h="{{.Hour}}" title="{{.Label}}"></div>{{end}}
          <div class="brush" id="brush"></div>
        </div>
      </div>
      <div class="axis"><span>{{.FirstLabel}}</span><span>{{.LastLabel}}</span></div>
    </section>
    {{end}}
  </div>
</header>

<main class="wrap">

  <div class="grid">

  <!-- Left: the inventory you browse. -->
  <section class="pane">
    <div class="pane-head">
      <h2>What is on the network</h2>
      <input class="search" id="q" type="search" placeholder="Filter…" aria-label="Filter devices">
      <span class="n" id="shown">{{.CountDevices}} devices</span>
    </div>
    <div class="scroll" id="list">
  {{range .Devices}}
  <details class="dev" data-a="{{.Buckets}}" data-cls="{{.Class}}" data-ev="{{.Events}}"
           data-proto="{{.Protocols}}" data-sev="{{.Severity}}"
           data-s="{{.IP}} {{.Hostname}} {{.Identity}} {{.Class}} {{.Vendor}} {{.Model}} {{.Firmware}} {{.Serial}} {{.OTIDs}} {{.Users}}"
           data-unk="{{if .Unknown}}1{{else}}0{{end}}"
           data-named="{{if .Hostname}}1{{else}}0{{end}}"
           style="--c:var(--c-{{.Class}})">
    <summary>
      <span class="ico" title="{{.ConfPct}}% confident">
        <svg class="ringc" viewBox="0 0 34 34" aria-hidden="true">
          <circle class="rbg" cx="17" cy="17" r="14"/>
          <circle class="rfg" cx="17" cy="17" r="14" stroke-dasharray="{{.RingDash}}"/>
        </svg>
        <span class="glyph">{{.Icon}}</span>
      </span>
      <div>
        <div class="addr-c">
          {{if .Severity}}<span class="dot {{.Severity}}" title="{{.Severity}} finding"></span>{{end}}
          {{.IP}}
        </div>
        {{if .Hostname}}<div class="host">{{.Hostname}}</div>{{end}}
      </div>
      <div>
        <div class="ident{{if .Unknown}} unk{{end}}">{{.Identity}}</div>
        <div class="tags">
          {{if .Users}}{{.Users}}{{end}}
          {{if .External}} →{{.External}} ext{{end}}
          {{if .Alerts}} <span class="warn">{{.Alerts}} alerts</span>{{end}}
        </div>
      </div>
      <span class="sparkbox">
        {{if .Spark}}<svg class="spark" viewBox="0 0 100 20" preserveAspectRatio="none">
          <polyline points="{{.Spark}}"/></svg>{{end}}
        <span class="sparksel"></span>
      </span>
      <span class="val">{{if .Unknown}}—{{else}}{{.ConfPct}}%{{end}}</span>
    </summary>
    <div class="ev">
      <dl class="facts">
        {{if .FirstSeen}}<div class="fact"><dt>seen</dt><dd>{{.FirstSeen}} → {{.LastSeen}}</dd></div>{{end}}
        {{if .MAC}}<div class="fact"><dt>hardware</dt><dd>{{.MAC}}{{if .RandomMAC}} <em>(randomised — not a stable identifier)</em>{{end}}{{if .Vendor}} · {{.Vendor}}{{end}}</dd></div>{{end}}
        {{if .Model}}<div class="fact"><dt>model</dt><dd>{{.Model}}</dd></div>{{end}}
        {{if .Firmware}}<div class="fact"><dt>firmware</dt><dd>{{.Firmware}}</dd></div>{{end}}
        {{if .Serial}}<div class="fact"><dt>serial</dt><dd>{{.Serial}}</dd></div>{{end}}
        {{if .OTIDs}}<div class="fact"><dt>control net</dt><dd>{{.OTIDs}}</dd></div>{{end}}
        {{if .Services}}<div class="fact"><dt>serving</dt><dd>{{.Services}}</dd></div>{{end}}
        {{if .Protocols}}<div class="fact"><dt>protocols</dt><dd>{{.Protocols}}</dd></div>{{end}}
        {{if .Users}}<div class="fact"><dt>users</dt><dd>{{.Users}}</dd></div>{{end}}
        {{if .Shares}}<div class="fact"><dt>shares</dt><dd>{{.Shares}}</dd></div>{{end}}
        {{if .External}}<div class="fact"><dt>external</dt><dd>{{.External}} destinations</dd></div>{{end}}
      </dl>
      {{if .Evidence}}
      <h3>Why we think so</h3>
      <table>
        <thead><tr><th>Signal</th><th>Observed</th><th>Implies</th><th style="text-align:right">Weight</th></tr></thead>
        <tbody>
        {{range .Evidence}}
          <tr><td>{{.Signal}}</td><td>{{.Value}}</td><td class="c">{{.Conclusion}}</td><td class="w">{{.Weight}}%</td></tr>
        {{end}}
        </tbody>
      </table>
      {{else}}<h3>No identifying signals seen</h3>{{end}}
    </div>
  </details>
  {{end}}
      <p class="empty" id="none" hidden>No devices match this filter.</p>
    </div>
  </section>

  <!-- Right: the issues you act on. -->
  <section class="pane">
    <div class="pane-head">
      <h2>Worth looking at</h2>
      <span class="n" id="find-n">{{.CountFindings}}</span>
    </div>
    <div class="scroll">
    {{if .Findings}}
      {{range .Findings}}
      <article class="find {{.Class}}" data-dev="{{.Device}}">
        <div class="top">
          <span class="sev">{{.Severity}}</span>
          <span class="addr">{{.Device}}</span>
        </div>
        <div class="what">{{.Title}}</div>
        <div class="why">{{.Detail}}</div>
        {{if .Fix}}<div class="fix"><b>Fix</b> {{.Fix}}</div>{{end}}
        {{if .Command}}<pre class="cmd"><code>{{.Command}}</code><button class="copy"
          type="button" aria-label="Copy command">Copy</button></pre>{{end}}
        {{if gt .Count 1}}<div class="rep">observed {{.Count}} times</div>{{end}}
      </article>
      {{end}}
      <p class="clear" id="find-none" hidden>Nothing needing attention in this window.</p>
      <p class="held" id="find-held" hidden><b id="find-held-n">0</b> more
        <span id="find-held-c"></span>on devices that were quiet in this window ·
        <button type="button" class="lnk" id="find-showall">show all</button></p>
    {{else}}
      <p class="clear">Nothing needing attention in this capture.</p>
    {{end}}
    </div>
  </section>

  </div><!-- /grid -->

  <!-- Panels recompute from the visible rows, so they always describe the
       window currently selected rather than the whole file. -->
  <div class="panels">
    <section class="panel">
      <h3>Device types <span id="range-note" class="muted"></span></h3>
      <div class="ring"><svg viewBox="0 0 42 42" id="ring"></svg>
        <div class="ring-c"><b id="ring-n">0</b><span>devices</span></div></div>
      <ul class="keys" id="keys-class"></ul>
    </section>
    <section class="panel">
      <h3>Busiest devices</h3>
      <ul class="bars2" id="top-talkers"></ul>
    </section>
    <section class="panel">
      <h3>Protocols in use</h3>
      <ul class="bars2" id="top-proto"></ul>
    </section>
    <section class="panel">
      <h3>Issues by severity</h3>
      <ul class="sevlist" id="sev-list"></ul>
      <p class="panel-foot" id="sev-foot"></p>
    </section>
  </div>

  <div class="sec"><h2>What the sensor could hear</h2><div class="rule"></div></div>
  <div class="cov">
    {{range .Coverage}}
    <div class="cv{{if not .Present}} off{{end}}">
      <span class="dt">{{if .Present}}●{{else}}○{{end}}</span>
      <span class="t">{{.Type}}</span>
      <span class="d">{{if .Present}}{{.Count}}{{else}}missing — no {{.Why}}{{end}}</span>
    </div>
    {{end}}
  </div>
  {{if .MissingTypes}}
  <p class="note"><b>{{.MissingTypes}} event types are not being logged.</b>
  Suricata can produce all of them; most builds ship with only alerts enabled. Turning the rest on
  costs nothing and is the difference between a partial list and a complete inventory. The
  <code>suricata.yaml</code> shipped with Tarsier enables everything.</p>
  {{end}}

  <footer>
    <p>
      Nothing was scanned or probed. Every device was found in existing traffic.<br>
      Identification is inference, not proof — each one shows its evidence.{{if .Skipped}}<br>
      {{comma .Skipped}} lines could not be parsed and were skipped.{{end}}
    </p>
    <p class="sig">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true">
        <circle cx="8" cy="11" r="5.4"/><circle cx="16" cy="11" r="5.4"/>
        <circle cx="9.4" cy="11" r="1.9" fill="currentColor" stroke="none"/>
        <circle cx="14.6" cy="11" r="1.9" fill="currentColor" stroke="none"/>
      </svg>
      Generated by <a href="https://github.com/kapoordeepanshu/tarsier">Tarsier</a> — free and open source
    </p>
  </footer>
</main>

<script>
(function(){
"use strict";
var r=document.documentElement,K="tarsier-theme";
try{var s=localStorage.getItem(K); if(s)r.setAttribute("data-theme",s);}catch(e){}
// Dark by default. This is a tool people look at in a server room or late in an
// incident, and it is the look the project leads with.
if(!r.getAttribute("data-theme")) r.setAttribute("data-theme","dark");
document.getElementById("t").addEventListener("click",function(){
  var n=r.getAttribute("data-theme")==="dark"?"light":"dark";
  r.setAttribute("data-theme",n);
  try{localStorage.setItem(K,n)}catch(e){}
});

var rows=[].slice.call(document.querySelectorAll(".dev")),
    bars=[].slice.call(document.querySelectorAll(".bar")),
    shown=document.getElementById("shown"),
    none=document.getElementById("none"),
    finds=[].slice.call(document.querySelectorAll(".find")),
    findNone=document.getElementById("find-none"),
    findHeld=document.getElementById("find-held"),
    q=document.getElementById("q"),
    sel=document.getElementById("sel"),
    brush=document.getElementById("brush"),
    plot=document.getElementById("plot"),
    note=document.getElementById("range-note"),
    NB=bars.length, lo=0, hi=NB-1, all=true, text="";

function setNum(id,v){var e=document.getElementById(id); if(e) e.textContent=v;}

var hourOf=bars.map(function(b){return +b.dataset.h;});
function css(n){return getComputedStyle(document.documentElement).getPropertyValue(n).trim();}
function stamp(i,end){
  if(!hourOf.length)return"";
  var h=hourOf[Math.min(Math.max(i,0),NB-1)]+(end?1:0);
  var d=new Date(h*3600*1000);
  return d.toLocaleDateString(undefined,{day:"numeric",month:"short"})+" "+
         d.toLocaleTimeString(undefined,{hour:"2-digit",minute:"2-digit"});
}

// A device is in the window if it was actually active in one of the selected
// buckets. Testing the span between first and last seen was the earlier bug:
// anything running all week overlaps every window, so nothing ever filtered.
function activeIn(row){
  if(all)return true;
  var a=row.dataset.a||"";
  for(var i=lo;i<=hi&&i<a.length;i++){ if(a.charCodeAt(i)>48) return true; }
  return false;
}

function apply(){
  var n=0, ident=0, named=0, cls={}, proto={}, sev={}, talkers=[], vis={};
  rows.forEach(function(row){
    var hit=activeIn(row);
    if(hit&&text) hit=row.dataset.s.toLowerCase().indexOf(text)>=0;
    row.hidden=!hit;
    if(!hit){ row.open=false; return; }
    n++;
    if(row.dataset.unk!=="1") ident++;
    if(row.dataset.named==="1") named++;
    vis[(row.dataset.s||"").split(" ")[0]]=1;
    cls[row.dataset.cls]=(cls[row.dataset.cls]||0)+1;
    (row.dataset.proto||"").split(" ").forEach(function(p){ if(p)proto[p]=(proto[p]||0)+1; });
    if(row.dataset.sev) sev[row.dataset.sev]=(sev[row.dataset.sev]||0)+1;
    // Weight by the share of activity inside the window, so "busiest" means
    // busiest during the selected period rather than overall.
    var a=row.dataset.a||"",tot=0,win=0;
    for(var i=0;i<a.length;i++){var v=a.charCodeAt(i)-48; tot+=v; if(i>=lo&&i<=hi)win+=v;}
    var ev=+row.dataset.ev||0;
    talkers.push({name:(row.dataset.s||"").split(" ")[0],
                  cls:row.dataset.cls,
                  v:all||!tot?ev:Math.round(ev*win/tot)});
  });

  // Findings follow the devices. A problem on a machine that was silent all
  // window is not something to act on right now, and leaving the count at the
  // whole-file total while the list below shrinks is the kind of small lie that
  // makes people stop believing the rest of the numbers.
  // Sensor-health findings are about the capture itself, so they always stand.
  var fn=0, fc=0, held=0, heldCrit=0;
  finds.forEach(function(f){
    var dev=f.dataset.dev||"", keep=all||dev==="sensor"||!!vis[dev];
    f.hidden=!keep;
    if(keep){ fn++; if(f.classList.contains("critical")) fc++; }
    else{ held++; if(f.classList.contains("critical")) heldCrit++; }
  });
  if(findNone) findNone.hidden=fn>0;
  if(findHeld){
    findHeld.hidden=!held;
    setNum("find-held-n",held);
    var hc=document.getElementById("find-held-c");
    if(hc) hc.textContent=heldCrit?"("+heldCrit+" critical) ":"";
  }

  shown.textContent=n+(n===1?" device":" devices");
  none.hidden=n>0;
  setNum("s-dev",n); setNum("s-ident",ident); setNum("s-named",named);
  setNum("s-find",fn); setNum("find-n",fn); setNum("s-crit",fc);
  var critCard=document.getElementById("s-crit-card");
  if(critCard) critCard.hidden=!fc;
  if(note) note.textContent=all?"whole capture":stamp(lo,0)+" — "+stamp(hi,1);

  bars.forEach(function(b,i){ b.classList.toggle("on",!all&&i>=lo&&i<=hi); });
  [].forEach.call(document.querySelectorAll(".sparksel"),function(s){
    if(all){ s.style.display="none"; return; }
    s.style.display="block";
    s.style.left=(lo/NB*100)+"%";
    s.style.width=((hi-lo+1)/NB*100)+"%";
  });

  drawRing(cls,n);
  drawBars("top-talkers",talkers.filter(function(t){return t.v>0})
      .sort(function(a,b){return b.v-a.v}).slice(0,6)
      .map(function(t){return{lb:t.name,v:t.v,c:"var(--c-"+t.cls+")"}}),"events");
  drawBars("top-proto",Object.keys(proto).map(function(k){return{lb:k,v:proto[k]}})
      .sort(function(a,b){return b.v-a.v}).slice(0,6),"devices");
  drawSev(sev);
}

function drawRing(cls,total){
  var svg=document.getElementById("ring"); if(!svg)return;
  document.getElementById("ring-n").textContent=total;
  var keys=Object.keys(cls).sort(function(a,b){return cls[b]-cls[a]}),
      C=2*Math.PI*15.9155, off=0, out="", legend="";
  if(!total){ svg.innerHTML='<circle cx="21" cy="21" r="15.9155" stroke="'+css("--rule")+'"/>';
    document.getElementById("keys-class").innerHTML=""; return; }
  keys.forEach(function(k){
    var frac=cls[k]/total, len=frac*C;
    out+='<circle cx="21" cy="21" r="15.9155" stroke="var(--c-'+k+')" '+
         'stroke-dasharray="'+len.toFixed(2)+' '+(C-len).toFixed(2)+'" '+
         'stroke-dashoffset="'+(-off).toFixed(2)+'"></circle>';
    legend+='<li><i style="background:var(--c-'+k+')"></i><b>'+cls[k]+'</b> '+k+'</li>';
    off+=len;
  });
  svg.innerHTML=out;
  document.getElementById("keys-class").innerHTML=legend;
}

function drawBars(id,items,unit){
  var el=document.getElementById(id); if(!el)return;
  if(!items.length){ el.innerHTML='<li class="muted">nothing in this window</li>'; return; }
  var peak=items[0].v||1;
  el.innerHTML=items.map(function(it){
    return '<li><span class="lb">'+esc(it.lb)+'</span><span class="vv">'+
      fmt(it.v)+'</span><span class="tr"><span class="fi" style="width:'+
      Math.max(it.v/peak*100,2)+'%'+(it.c?';background:'+it.c:'')+'"></span></span></li>';
  }).join("");
}

function drawSev(sev){
  var order=["critical","high","medium","low"],el=document.getElementById("sev-list");
  if(!el)return;
  var any=order.some(function(s){return sev[s]});
  el.innerHTML=any?order.filter(function(s){return sev[s]}).map(function(s){
    return '<li><span class="sq" style="background:var(--'+
      (s==="critical"?"crit":s==="high"?"high":s==="medium"?"med":"low")+')"></span>'+
      s+'<span class="ct">'+sev[s]+'</span></li>';
  }).join(""):'<li class="muted">no issues on visible devices</li>';
  var foot=document.getElementById("sev-foot");
  if(foot) foot.textContent=any?"devices carrying at least one finding":"";
}

function esc(s){return String(s).replace(/[&<>"]/g,function(c){
  return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c];});}
function fmt(n){return n>=1000?(n/1000).toFixed(1)+"k":n;}

function setRange(a,b,isAll){
  all=!!isAll; lo=Math.max(0,a); hi=Math.min(NB-1,b);
  if(brush){
    if(all){ brush.style.display="none"; }
    else{ brush.style.display="block";
      brush.style.left=(lo/NB*100)+"%";
      brush.style.width=((hi-lo+1)/NB*100)+"%"; }
  }
  if(sel) sel.textContent=all?document.querySelector(".axis span").textContent+" — "+
      document.querySelectorAll(".axis span")[1].textContent
    :stamp(lo,0)+" — "+stamp(hi,1);
  apply();
}

var presets=[].slice.call(document.querySelectorAll(".chip[data-h],.chip[data-all]")),
    perBucket=NB>1?(hourOf[1]-hourOf[0])||1:1,
    spanHours=NB*perBucket;

function clearChips(){
  presets.forEach(function(o){ o.setAttribute("aria-pressed","false"); });
}

// Presets behave as one control with exactly one choice active, rather than as
// toggles that clear on a second click — that was only discoverable by reading
// the hint text. "All" is now a button of its own, so the way out is visible.
//
// A preset wider than the data would select the whole capture under a label
// that says otherwise. The first one that covers everything is kept, since it
// honestly reads as "all of it", and anything longer is disabled.
(function(){
  var covered=false;
  presets.forEach(function(c){
    if(!c.dataset.h) return;
    if(covered){ c.disabled=true; return; }
    if(+c.dataset.h>=spanHours) covered=true;
  });
})();

var allChip=presets.filter(function(c){return c.dataset.all})[0];
var showAll=document.getElementById("find-showall");
if(showAll&&allChip) showAll.addEventListener("click",function(){ allChip.click(); });

// Presets measure back from the end of the capture, not from now: this is a
// record of a period that has already happened.
presets.forEach(function(c){
  c.addEventListener("click",function(){
    if(c.disabled||!NB) return;
    clearChips();
    c.setAttribute("aria-pressed","true");
    if(c.dataset.all){ setRange(0,NB-1,true); return; }
    setRange(Math.max(0,NB-Math.ceil(+c.dataset.h/perBucket)),NB-1,false);
  });
});

if(plot&&NB){
  var dragging=false,anchor=0;
  var idxAt=function(ev){
    var rect=plot.getBoundingClientRect(),
        x=Math.min(Math.max(ev.clientX-rect.left,0),rect.width);
    return Math.min(NB-1,Math.floor(x/rect.width*NB));
  };
  plot.addEventListener("pointerdown",function(ev){
    dragging=true; anchor=idxAt(ev); plot.setPointerCapture(ev.pointerId);
    [].forEach.call(document.querySelectorAll(".chip"),function(o){o.setAttribute("aria-pressed","false")});
    setRange(anchor,anchor,false);
  });
  plot.addEventListener("pointermove",function(ev){
    if(!dragging)return;
    var i=idxAt(ev);
    setRange(Math.min(anchor,i),Math.max(anchor,i),false);
  });
  var end=function(){
    if(!dragging)return;
    dragging=false;
    // A click rather than a drag clears the selection.
    if(hi-lo<1) setRange(0,NB-1,true);
  };
  plot.addEventListener("pointerup",end);
  plot.addEventListener("pointercancel",end);
}

// Copy buttons on fix commands. The whole point is that the fix is one action
// away, so make the last step trivial too.
[].forEach.call(document.querySelectorAll(".copy"),function(b){
  b.addEventListener("click",function(){
    var code=b.parentNode.querySelector("code");
    if(!code)return;
    var done=function(){ b.textContent="Copied"; setTimeout(function(){b.textContent="Copy"},1600); };
    if(navigator.clipboard&&navigator.clipboard.writeText){
      navigator.clipboard.writeText(code.textContent).then(done,function(){});
    }else{
      // Offline files are often opened over file://, where the clipboard API
      // is unavailable. Select the text so Ctrl+C still works.
      var r=document.createRange(); r.selectNodeContents(code);
      var s=window.getSelection(); s.removeAllRanges(); s.addRange(r);
      b.textContent="Press Ctrl+C";
      setTimeout(function(){b.textContent="Copy"},2400);
    }
  });
});

if(q) q.addEventListener("input",function(){ text=q.value.trim().toLowerCase(); apply(); });

// Open on the last 24 hours. That is the window someone actually checks, and
// showing the whole file by default buries a day's worth of change in a month
// of history. Captures shorter than a day open in full, because a "24 hours"
// label over three hours of data would be a lie.
(function(){
  var c24=presets.filter(function(c){return c.dataset.h==="24"})[0],
      start=(spanHours>24&&c24)?c24:allChip;
  if(start) start.click(); else setRange(0,NB-1,true);
})();
})();
</script>
</body>
</html>`
