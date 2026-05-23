import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'

/* ─── inline styles scoped to .landing so they never leak into the dashboard ─── */
const STYLES = `
.landing *{margin:0;padding:0;box-sizing:border-box}
.landing{background:#060608;color:#f5f0e8;font-family:'Geist','Inter',ui-sans-serif,system-ui,-apple-system,sans-serif;overflow-x:hidden}
.landing a{text-decoration:none;color:inherit}
.landing button{cursor:pointer;font-family:inherit}

/* NAV */
.l-nav{position:fixed;top:0;left:0;right:0;z-index:200;display:flex;align-items:center;justify-content:space-between;padding:0 40px;height:60px;background:#060608;border-bottom:1px solid rgba(255,255,255,.08)}
.l-nav-logo{font-size:22px;font-weight:700;color:#f5f0e8;letter-spacing:-.5px}
.l-nav-links{display:flex;gap:28px;list-style:none}
.l-nav-links a{color:rgba(245,240,232,.55);font-size:13px;font-weight:500;letter-spacing:1.5px;text-transform:uppercase;transition:color .2s}
.l-nav-links a:hover{color:#f5f0e8}
.l-nav-actions{display:flex;gap:10px;align-items:center}
.btn-nav-ghost{padding:7px 18px;font-size:13px;color:rgba(245,240,232,.6);background:transparent;border:1px solid rgba(245,240,232,.2);cursor:pointer;font-family:inherit;letter-spacing:.5px;transition:all .2s;text-decoration:none;display:inline-block}
.btn-nav-ghost:hover{color:#f5f0e8;border-color:rgba(245,240,232,.5)}
.btn-nav-red{padding:7px 20px;font-size:13px;font-weight:600;color:#fff;background:#e8182c;border:none;cursor:pointer;font-family:inherit;letter-spacing:1px;text-transform:uppercase;transition:all .2s;text-decoration:none;display:inline-block}
.btn-nav-red:hover{background:#ff2a3e}

/* HERO */
.l-hero{margin-top:60px;min-height:calc(100vh - 60px);position:relative;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;overflow:hidden}
.l-hero-bg{position:absolute;inset:0;background:radial-gradient(ellipse 80% 55% at 50% 36%,rgba(0,80,180,.14),transparent),radial-gradient(ellipse 48% 38% at 50% 36%,rgba(0,229,200,.07),transparent),#060608}
.l-hero-grain{position:absolute;inset:0;background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.75' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.08'/%3E%3C/svg%3E");pointer-events:none}
.l-hero-content{position:relative;z-index:2;padding:0 24px}
.l-hero h1{font-size:clamp(48px,7vw,96px);font-weight:900;line-height:1.02;letter-spacing:-2px;color:#f5f0e8;max-width:820px;margin:0 auto}
.l-hero h1 em{font-style:italic;color:#f5f0e8}
.l-hero-sub{margin-top:24px;font-size:18px;font-weight:400;color:rgba(245,240,232,.86);max-width:520px;margin-left:auto;margin-right:auto;line-height:1.6}
.l-hero-actions{margin-top:40px;display:flex;gap:16px;justify-content:center;align-items:center}
.btn-red-hero{padding:14px 36px;font-size:13px;font-weight:600;color:#fff;background:#e8182c;border:none;cursor:pointer;font-family:inherit;letter-spacing:2px;text-transform:uppercase;transition:all .25s;text-decoration:none;display:inline-block}
.btn-red-hero:hover{background:#ff2a3e;transform:translateY(-2px)}
.btn-docs-hero{font-size:13px;font-weight:500;color:rgba(245,240,232,.88);text-decoration:none;letter-spacing:1px;text-transform:uppercase;border-bottom:1px solid rgba(245,240,232,.44);padding-bottom:2px;transition:color .2s}
.btn-docs-hero:hover{color:#f5f0e8}
.l-hero-trusted{position:relative;z-index:2;margin-top:60px;padding-top:24px;border-top:1px solid rgba(245,240,232,.14)}
.l-hero-trusted p{font-size:13px;font-weight:600;letter-spacing:3px;text-transform:uppercase;color:rgba(245,240,232,.70);margin-bottom:16px}
.trusted-row{display:flex;gap:36px;justify-content:center;align-items:center;flex-wrap:wrap}
.trusted-name{font-size:14px;font-weight:600;color:rgba(245,240,232,.70)}

/* ARCH SPLIT */
.arch-container{display:flex;align-items:stretch;min-height:500px}
.arch-left{flex:1;background:linear-gradient(135deg,#00c896,#00e5c8,#00aaff,#0066ff);position:relative;overflow:hidden;display:flex;align-items:flex-end;padding:48px}
.arch-left::before{content:'';position:absolute;inset:0;background:repeating-conic-gradient(from 0deg at 50% 100%,rgba(255,255,255,.06) 0deg,transparent 3deg,transparent 8deg)}
.arch-left h2{font-size:clamp(32px,4vw,52px);font-weight:400;font-style:italic;color:#0a2010;position:relative;z-index:1;line-height:1.1}
.arch-right{flex:1;background:linear-gradient(135deg,#4400cc,#7c3aed,#c8006a,#ff3366);position:relative;overflow:hidden;display:flex;align-items:center;padding:48px}
.arch-right::before{content:'';position:absolute;inset:0;background:repeating-conic-gradient(from 0deg at 50% 100%,rgba(255,255,255,.05) 0deg,transparent 3deg,transparent 8deg)}
.arch-right p{font-size:17px;line-height:1.7;color:rgba(255,255,255,.9);position:relative;z-index:1;font-weight:300}
.orb{width:80px;height:80px;border-radius:50%;background:conic-gradient(from 0deg,#00c896,#0066ff,#7c3aed,#ff3366,#ff6b35,#00c896);position:absolute;bottom:-40px;left:50%;transform:translateX(-50%);box-shadow:0 0 40px rgba(0,229,200,.5),0 0 80px rgba(124,58,237,.3),inset 0 0 20px rgba(255,255,255,.2);animation:orbBob 3s ease-in-out infinite alternate,orbSpin 6s linear infinite;z-index:10}
.orb-rings{position:absolute;width:80px;height:80px;border-radius:50%;border:1px solid rgba(255,255,255,.3);animation:orbRings 3s ease-in-out infinite alternate}
@keyframes orbBob{from{transform:translateX(-50%) translateY(0)}to{transform:translateX(-50%) translateY(-8px)}}
@keyframes orbSpin{to{filter:hue-rotate(360deg)}}
@keyframes orbRings{0%{transform:scale(1);opacity:.5}100%{transform:scale(1.3);opacity:0}}

/* FLOW SECTION */
.l-flow-section{background:#060608;padding:80px 60px;position:relative}
.l-flow-title{text-align:center;margin-bottom:64px}
.l-flow-title h2{font-size:clamp(36px,5vw,64px);font-weight:900;line-height:1.05;letter-spacing:-2px}
.l-flow-title p{margin-top:14px;font-size:17px;color:rgba(245,240,232,.5);max-width:480px;margin-left:auto;margin-right:auto;line-height:1.6}
.flow-diagram-wrap{position:relative;display:grid;grid-template-columns:minmax(0,1fr) 320px;gap:28px;align-items:stretch;max-width:1180px;margin:0 auto;padding:20px;border:1px solid rgba(245,240,232,.08);background:radial-gradient(circle at 34% 24%,rgba(0,229,200,.055),transparent 32%),rgba(245,240,232,.025);overflow:hidden}
.flow-diagram-wrap::before{content:'';position:absolute;inset:0;background-image:linear-gradient(rgba(245,240,232,.035) 1px,transparent 1px),linear-gradient(90deg,rgba(245,240,232,.035) 1px,transparent 1px);background-size:32px 32px;pointer-events:none}
.active-flow-canvas{position:relative;z-index:1;min-height:590px;border:1px solid rgba(245,240,232,.14);background:rgba(6,6,8,.94);box-shadow:0 0 0 1px rgba(0,229,200,.05),0 10px 44px rgba(0,0,0,.50),inset 0 1px 0 rgba(245,240,232,.04);overflow:hidden}
.active-flow-canvas svg{width:100%;height:100%;min-height:590px;display:block;position:relative;z-index:1}
.node-box{fill:rgba(245,240,232,.09);stroke:rgba(245,240,232,.20);stroke-width:1.4}
.node-box.hot{stroke:rgba(0,229,200,.65);filter:drop-shadow(0 0 14px rgba(0,229,200,.22))}
.agent-node .node-box{stroke:rgba(46,168,255,.75)!important;filter:drop-shadow(0 0 14px rgba(46,168,255,.18))!important}
.mcp-node .node-box{stroke:rgba(200,240,0,.75)!important;filter:drop-shadow(0 0 14px rgba(200,240,0,.18))!important}
.node-box.warn{stroke:rgba(255,107,53,.72);filter:drop-shadow(0 0 16px rgba(255,107,53,.22))}
.node-title{fill:#f5f0e8;font-family:'Geist','Inter',sans-serif;font-size:17px;font-weight:750;letter-spacing:-.2px}
.node-kicker,.stage-kicker{fill:rgba(245,240,232,.92);font-family:'DM Mono',monospace;font-size:13px;letter-spacing:1.4px;text-transform:uppercase}
.node-small{fill:rgba(245,240,232,.92);font-family:'Geist','Inter',sans-serif;font-size:14px;font-weight:500}
.stage-card rect{fill:rgba(245,240,232,.10);stroke:rgba(0,229,200,.34);stroke-width:1.2}
.stage-card text{fill:rgba(245,240,232,.92);font-family:'Geist','Inter',sans-serif;font-size:14px;font-weight:650}
.stage-dot{fill:rgba(0,229,200,.52)}
.stage-card{animation:stageWakeClean 9s ease-in-out infinite}
.stage-1{animation-delay:.3s}.stage-2{animation-delay:.85s}.stage-3{animation-delay:1.4s}.stage-4{animation-delay:1.95s}.stage-5{animation-delay:2.5s}
@keyframes stageWakeClean{0%,100%{filter:none}12%,28%{filter:drop-shadow(0 0 14px rgba(0,229,200,.30))}}
.flow-path{fill:none;stroke:rgba(245,240,232,.20);stroke-width:1.5;stroke-dasharray:7 9;animation:lineFlow 1.8s linear infinite;vector-effect:non-scaling-stroke}
.flow-path.primary{stroke:rgba(0,229,200,.56)}
.flow-path.allow{stroke:rgba(200,240,0,.50)}
.flow-path.quarantine{stroke:rgba(255,107,53,.66)}
.flow-path.audit{stroke:rgba(124,58,237,.66)}
@keyframes lineFlow{to{stroke-dashoffset:-32}}
.packet{filter:drop-shadow(0 0 8px rgba(0,229,200,.70))}
.packet.allow{fill:#c8f000;filter:drop-shadow(0 0 8px rgba(200,240,0,.65))}
.packet.quarantine{fill:#ff6b35;filter:drop-shadow(0 0 9px rgba(255,107,53,.76))}
.packet.audit{fill:#7c3aed;filter:drop-shadow(0 0 9px rgba(124,58,237,.76))}
.pulse-ring{fill:none;stroke:rgba(0,229,200,.50);stroke-width:1.4;animation:ringPulse 2.8s ease-out infinite;transform-box:fill-box;transform-origin:center}
.pulse-ring.warn{stroke:rgba(255,107,53,.58);animation-delay:1.2s}
.pulse-ring.audit{stroke:rgba(124,58,237,.62);animation-delay:2s}
@keyframes ringPulse{0%{opacity:.9;transform:scale(.84)}70%,100%{opacity:0;transform:scale(1.55)}}
.gateway-shell{fill:rgba(6,6,8,.78);stroke:rgba(0,229,200,.55);stroke-width:1.4;filter:drop-shadow(0 0 26px rgba(0,229,200,.16))}
.gateway-label{fill:#f5f0e8;font-family:'Geist','Inter',sans-serif;font-size:19px;font-weight:800;letter-spacing:-.3px}
.gateway-sub{fill:rgba(245,240,232,.70);font-family:'DM Mono',monospace;font-size:13px;letter-spacing:1.5px}
.active-status-panel{position:relative;z-index:1;display:flex;flex-direction:column;gap:14px;padding:20px;border:1px solid rgba(245,240,232,.10);background:rgba(6,6,8,.78);min-height:520px}
.status-panel-top{display:flex;justify-content:space-between;gap:12px;align-items:center;padding-bottom:14px;border-bottom:1px solid rgba(245,240,232,.08)}
.status-panel-title{font-size:15px;font-weight:750;color:#f5f0e8}
.status-live{display:inline-flex;align-items:center;gap:7px;font-size:13px;font-family:'DM Mono',monospace;color:rgba(245,240,232,.78)}
.status-live::before{content:'';width:7px;height:7px;border-radius:999px;background:#00e5c8;box-shadow:0 0 14px rgba(0,229,200,.55)}
.l-status-card{border:1px solid rgba(245,240,232,.10);background:rgba(245,240,232,.04);padding:14px}
.l-status-label{font-family:'DM Mono',monospace;font-size:13px;letter-spacing:1.6px;color:rgba(245,240,232,.62);text-transform:uppercase;margin-bottom:7px}
.l-status-value{font-size:16px;line-height:1.45;color:rgba(245,240,232,.92);font-weight:650;word-break:break-word}
.l-status-decision{display:inline-flex;align-items:center;gap:8px;padding:8px 10px;border:1px solid rgba(255,107,53,.36);background:rgba(255,107,53,.08);color:#ff6b35;font-family:'DM Mono',monospace;font-size:14px;font-weight:700;letter-spacing:1px}
.l-status-decision.allow{color:#c8f000;border-color:rgba(200,240,0,.34);background:rgba(200,240,0,.08)}
.l-status-decision.monitor{color:#00e5c8;border-color:rgba(0,229,200,.34);background:rgba(0,229,200,.07)}
.status-timeline{display:grid;gap:10px;margin-top:auto}
.status-step{display:grid;grid-template-columns:22px 1fr;gap:10px;align-items:start;font-size:14px;line-height:1.45;color:rgba(245,240,232,.78)}
.status-step-dot{width:22px;height:22px;border:1px solid rgba(0,229,200,.35);display:grid;place-items:center;color:#00e5c8;font-family:'DM Mono',monospace;font-size:13px}

/* LAYERS */
.l-layers-section{background:#060608;padding:80px 60px;border-top:1px solid rgba(245,240,232,.06)}
.l-layers-header{text-align:center;margin-bottom:60px}
.l-layers-header h2{font-size:clamp(36px,5vw,60px);font-weight:900;letter-spacing:-2px}
.l-layers-header p{margin-top:14px;font-size:17px;color:rgba(245,240,232,.78);max-width:500px;margin-left:auto;margin-right:auto}
.layers-pipeline{display:flex;align-items:stretch;border:1px solid rgba(245,240,232,.08);overflow:hidden}
.pipeline-step{flex:1;padding:32px 24px;border-right:1px solid rgba(245,240,232,.06);position:relative;transition:background .3s;overflow:hidden}
.pipeline-step:last-child{border-right:none}
.pipeline-step::after{content:'→';position:absolute;right:-12px;top:50%;transform:translateY(-50%);font-size:16px;color:rgba(245,240,232,.2);z-index:2}
.pipeline-step:last-child::after{display:none}
.pipeline-step:hover{background:rgba(245,240,232,.03)}
.pipeline-step::before{content:'';position:absolute;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,#00e5c8,transparent);top:0;animation:scanBar 3s ease-in-out infinite;opacity:0}
.pipeline-step:nth-child(1)::before{animation-delay:0s}.pipeline-step:nth-child(2)::before{animation-delay:.4s}.pipeline-step:nth-child(3)::before{animation-delay:.8s}.pipeline-step:nth-child(4)::before{animation-delay:1.2s}.pipeline-step:nth-child(5)::before{animation-delay:1.6s}
@keyframes scanBar{0%,100%{top:0;opacity:0}10%{opacity:1}90%{opacity:1}95%{top:100%;opacity:0}}
.step-num{font-family:'DM Mono',monospace;font-size:13px;color:#00e5c8;letter-spacing:2px;margin-bottom:12px}
.step-name{font-size:16px;font-weight:700;margin-bottom:8px}
.step-desc{font-size:15px;color:rgba(245,240,232,.72);line-height:1.6}
.step-tag{display:inline-block;margin-top:14px;font-family:'DM Mono',monospace;font-size:13px;padding:3px 8px;letter-spacing:1px}
.tag-cyan{background:rgba(0,229,200,.1);color:#00e5c8;border:1px solid rgba(0,229,200,.2)}
.tag-red{background:rgba(232,24,44,.1);color:#ff4455;border:1px solid rgba(232,24,44,.2)}
.tag-lime{background:rgba(200,240,0,.1);color:#c8f000;border:1px solid rgba(200,240,0,.2)}

/* SPLIT SECTIONS */
.split-section{display:flex;min-height:600px;border-top:1px solid rgba(245,240,232,.06)}
.split-left{flex:1;padding:64px 60px;display:flex;flex-direction:column;justify-content:flex-end;position:relative;overflow:hidden}
.split-right{flex:1;background:#060608;border-left:1px solid rgba(245,240,232,.08);display:flex;flex-direction:column;justify-content:center;padding:64px 60px;position:relative;overflow:hidden}
.split-right::before{content:'';position:absolute;inset:0;background:repeating-conic-gradient(from 0deg at 80% 80%,rgba(245,240,232,.02) 0deg,transparent 2deg,transparent 6deg)}
.split-label{font-size:13px;font-weight:600;letter-spacing:3px;text-transform:uppercase;color:rgba(245,240,232,.3);font-family:'DM Mono',monospace;margin-bottom:20px}
.split-title{font-size:clamp(28px,3.5vw,44px);font-weight:700;line-height:1.1;letter-spacing:-1px;margin-bottom:20px}
.split-body{font-size:16px;color:rgba(245,240,232,.78);line-height:1.7;font-weight:300;max-width:440px;margin-bottom:28px}
.btn-outline{display:inline-block;padding:10px 22px;font-size:13px;font-weight:600;color:#f5f0e8;background:transparent;border:1px solid rgba(245,240,232,.3);cursor:pointer;font-family:inherit;letter-spacing:2px;text-transform:uppercase;transition:all .2s;text-decoration:none}
.btn-outline:hover{border-color:#f5f0e8}

/* AUDIT TERMINAL */
.audit-terminal{background:#080b10;border:1px solid rgba(245,240,232,.1);border-radius:4px;overflow:hidden;font-family:'DM Mono',monospace;font-size:13px;position:relative}
.terminal-bar{background:#111820;padding:10px 16px;display:flex;align-items:center;gap:6px;border-bottom:1px solid rgba(245,240,232,.08)}
.t-dot{width:10px;height:10px;border-radius:50%}
.t-red{background:#ff5f57}.t-yellow{background:#ffbd2e}.t-green{background:#28c840}
.terminal-title{margin-left:8px;font-size:13px;color:rgba(245,240,232,.3);letter-spacing:1px}
.terminal-body{padding:16px}
.t-row{display:flex;gap:12px;align-items:center;padding:6px 0;border-bottom:1px solid rgba(245,240,232,.04);opacity:0;animation:rowAppear .3s ease forwards}
.t-row:nth-child(1){animation-delay:.1s}.t-row:nth-child(2){animation-delay:.6s}.t-row:nth-child(3){animation-delay:1.1s}.t-row:nth-child(4){animation-delay:1.6s}.t-row:nth-child(5){animation-delay:2.1s}.t-row:nth-child(6){animation-delay:2.6s}
@keyframes rowAppear{from{opacity:0;transform:translateX(-8px)}to{opacity:1;transform:none}}
.t-time{color:rgba(245,240,232,.3);min-width:70px;font-size:13px}
.t-action{flex:1;color:rgba(245,240,232,.8);font-size:13px}
.t-badge{padding:2px 8px;font-size:13px;font-weight:700;letter-spacing:1px;border-radius:2px}
.b-allow{background:rgba(0,229,200,.15);color:#00e5c8;border:1px solid rgba(0,229,200,.3)}
.b-block{background:rgba(232,24,44,.15);color:#ff4455;border:1px solid rgba(232,24,44,.3)}
.b-monitor{background:rgba(255,204,0,.12);color:#ffcc00;border:1px solid rgba(255,204,0,.3)}
.b-quarantine{background:rgba(255,107,53,.12);color:#ff6b35;border:1px solid rgba(255,107,53,.3)}

/* CODE DISPLAY */
.code-display{background:#060608;border:1px solid rgba(245,240,232,.1);border-radius:4px;overflow:hidden}
.code-tabs{display:flex;background:#0d1117;border-bottom:1px solid rgba(245,240,232,.08)}
.code-tab{padding:10px 20px;font-size:13px;font-weight:500;color:rgba(245,240,232,.4);cursor:pointer;border-bottom:2px solid transparent;font-family:inherit;background:transparent;transition:all .2s}
.code-tab.active{color:#f5f0e8;border-bottom-color:#00e5c8}
.code-body{padding:24px;font-family:'DM Mono',monospace;font-size:14px;line-height:2}
.ck{color:#66aaff}.cs{color:#00e5c8}.cm{color:rgba(245,240,232,.25)}.cf{color:#ff9966}.cn{color:#ffcc00}

/* COLOR SPLIT */
.color-split{display:grid;grid-template-columns:1fr 1fr;min-height:520px}
.cs-block{padding:60px 52px;position:relative;overflow:hidden;display:flex;flex-direction:column;justify-content:flex-end}
.cs-block::before{content:'';position:absolute;inset:0;background:repeating-conic-gradient(from 0deg at 50% 100%,rgba(255,255,255,.04) 0deg,transparent 2deg,transparent 7deg)}
.cs-cyan{background:linear-gradient(135deg,#003d36,#006654,#00e5c8)}
.cs-lime{background:linear-gradient(135deg,#3a4700,#6a8000,#c8f000)}
.cs-red{background:linear-gradient(135deg,#3d000a,#880018,#e8182c)}
.cs-purple{background:linear-gradient(135deg,#1a0040,#4400cc,#9933ff)}
.cs-block h3{font-size:clamp(22px,2.5vw,30px);font-weight:700;color:#f5f0e8;position:relative;z-index:1;margin-bottom:14px;line-height:1.2}
.cs-block p{font-size:16px;color:rgba(255,255,255,.78);line-height:1.6;font-weight:300;position:relative;z-index:1;max-width:340px}
.cs-icon{font-size:36px;margin-bottom:20px;position:relative;z-index:1}

/* METRICS STRIP */
.l-metrics-strip{background:#060608;border-top:1px solid rgba(245,240,232,.06);border-bottom:1px solid rgba(245,240,232,.06);display:grid;grid-template-columns:repeat(4,1fr)}
.l-metric-block{padding:52px 40px;border-right:1px solid rgba(245,240,232,.06);transition:background .3s}
.l-metric-block:last-child{border-right:none}
.l-metric-block:hover{background:rgba(245,240,232,.02)}
.l-metric-num{font-size:56px;font-weight:900;letter-spacing:-3px;line-height:1;color:#f5f0e8;margin-bottom:8px}
.l-metric-num span{color:#00e5c8}
.l-metric-desc{font-size:15px;color:rgba(245,240,232,.72);line-height:1.5}

/* PRICING */
.l-pricing-section{background:#060608;padding:80px 60px;text-align:center}
.l-pricing-section h2{font-size:clamp(36px,5vw,60px);font-weight:900;letter-spacing:-2px;margin-bottom:14px}
.l-pricing-section>p{font-size:17px;color:rgba(245,240,232,.78);margin-bottom:60px}
.pricing-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:1px;background:rgba(245,240,232,.08);border:1px solid rgba(245,240,232,.08);max-width:900px;margin:0 auto}
.price-block{background:#060608;padding:44px 36px;text-align:left;transition:background .3s;position:relative}
.price-block:hover{background:#0a0e14}
.price-block.featured{background:#0a0e14}
.price-block.featured::after{content:'POPULAR';position:absolute;top:0;right:0;background:#e8182c;color:#fff;font-family:'DM Mono',monospace;font-size:13px;font-weight:700;letter-spacing:2px;padding:4px 12px}
.price-tier{font-family:'DM Mono',monospace;font-size:13px;letter-spacing:3px;text-transform:uppercase;color:rgba(245,240,232,.4);margin-bottom:24px}
.price-amount{font-size:52px;font-weight:900;letter-spacing:-3px;line-height:1;margin-bottom:6px}
.price-period{font-size:13px;color:rgba(245,240,232,.35);margin-bottom:32px}
.price-features{list-style:none;display:flex;flex-direction:column;gap:12px;margin-bottom:36px}
.price-features li{font-size:15px;color:rgba(245,240,232,.72);display:flex;gap:10px}
.price-features li::before{content:'—';color:#00e5c8;font-family:'DM Mono',monospace;flex-shrink:0}
.price-features li.off{color:rgba(245,240,232,.25)}
.price-features li.off::before{color:rgba(245,240,232,.15)}
.btn-price{width:100%;padding:12px;font-size:13px;font-weight:600;letter-spacing:2px;text-transform:uppercase;cursor:pointer;font-family:inherit;transition:all .2s;border:1px solid rgba(245,240,232,.25);background:transparent;color:#f5f0e8;display:block;text-align:center;text-decoration:none}
.btn-price:hover{border-color:#f5f0e8}
.btn-price.red-btn{background:#e8182c;border-color:#e8182c}
.btn-price.red-btn:hover{background:#ff2a3e}

/* FINAL CTA */
.final-cta{display:grid;grid-template-columns:1fr 1fr;min-height:400px}
.cta-left{background:linear-gradient(135deg,#c8f000,#80cc00,#33aa00);padding:60px;display:flex;flex-direction:column;justify-content:flex-end;position:relative;overflow:hidden}
.cta-left::before{content:'';position:absolute;inset:0;background:repeating-conic-gradient(from 0deg at 0% 100%,rgba(255,255,255,.05) 0deg,transparent 3deg,transparent 8deg)}
.cta-left h2{font-size:clamp(28px,3.5vw,44px);font-weight:900;color:#0a2000;position:relative;z-index:1;line-height:1.1;letter-spacing:-1px;margin-bottom:24px}
.cta-left .cta-actions{display:flex;gap:14px;position:relative;z-index:1}
.btn-cta-black{padding:12px 28px;font-size:13px;font-weight:600;color:#fff;background:#0a2000;border:none;cursor:pointer;font-family:inherit;letter-spacing:2px;text-transform:uppercase;transition:all .2s;text-decoration:none;display:inline-block}
.btn-cta-docs{padding:12px 24px;font-size:13px;font-weight:600;color:#0a2000;background:transparent;border:1px solid rgba(10,32,0,.4);cursor:pointer;font-family:inherit;letter-spacing:2px;text-transform:uppercase;transition:all .2s;text-decoration:none;display:inline-block}
.cta-right{background:linear-gradient(135deg,#1a0040,#7c3aed,#c026d3);padding:60px;display:flex;flex-direction:column;justify-content:flex-end;position:relative;overflow:hidden}
.cta-right::before{content:'';position:absolute;inset:0;background:repeating-conic-gradient(from 0deg at 100% 100%,rgba(255,255,255,.04) 0deg,transparent 3deg,transparent 8deg)}
.cta-right h2{font-size:clamp(28px,3.5vw,44px);font-weight:900;font-style:italic;color:rgba(255,255,255,.9);position:relative;z-index:1;line-height:1.1;letter-spacing:-1px;margin-bottom:24px}
.btn-cta-white{display:inline-block;padding:12px 28px;font-size:13px;font-weight:600;color:#1a0040;background:#fff;border:none;cursor:pointer;font-family:inherit;letter-spacing:2px;text-transform:uppercase;transition:all .2s;text-decoration:none;position:relative;z-index:1}
.btn-cta-white:hover{background:#f5f0e8}

/* FOOTER */
.l-footer{background:#060608;border-top:1px solid rgba(245,240,232,.08);padding:52px 60px 32px}
.footer-grid{display:grid;grid-template-columns:1.5fr 1fr 1fr 1fr 1fr;gap:40px;margin-bottom:52px}
.footer-brand-name{font-size:24px;font-weight:700;color:#f5f0e8;margin-bottom:12px}
.footer-brand p{font-size:15px;color:rgba(245,240,232,.72);line-height:1.7;max-width:220px}
.footer-col h5{font-size:13px;font-weight:600;letter-spacing:3px;text-transform:uppercase;color:rgba(245,240,232,.3);font-family:'DM Mono',monospace;margin-bottom:20px}
.footer-col a{display:block;font-size:14px;color:rgba(245,240,232,.45);text-decoration:none;margin-bottom:12px;transition:color .2s;letter-spacing:.3px}
.footer-col a:hover{color:#f5f0e8}
.footer-bottom{border-top:1px solid rgba(245,240,232,.06);padding-top:24px;display:flex;align-items:center;justify-content:space-between;font-size:14px;color:rgba(245,240,232,.25);font-family:'DM Mono',monospace;letter-spacing:.5px}

/* RESPONSIVE */
@media(max-width:1100px){
  .l-nav{height:auto;min-height:64px;padding:14px 24px;flex-wrap:wrap;gap:14px}
  .l-nav-links{order:3;width:100%;justify-content:center;flex-wrap:wrap;gap:16px}
  .arch-container,.split-section,.final-cta{flex-direction:column}
  .flow-diagram-wrap{grid-template-columns:1fr}
  .layers-pipeline,.pricing-grid,.l-metrics-strip{grid-template-columns:1fr}
  .pipeline-step{border-right:none;border-bottom:1px solid rgba(245,240,232,.08)}
  .color-split{grid-template-columns:1fr}
  .footer-grid{grid-template-columns:1fr 1fr}
}
@media(max-width:760px){
  .l-nav-links{display:none}
  .l-hero{min-height:auto;padding:72px 0}
  .l-hero h1{font-size:clamp(38px,12vw,54px)}
  .l-hero-actions,.cta-left .cta-actions{flex-direction:column;align-items:stretch}
  .arch-left,.arch-right,.split-left,.split-right,.cta-left,.cta-right,.l-footer,.l-flow-section,.l-layers-section,.l-pricing-section{padding-left:24px;padding-right:24px}
  .footer-bottom{flex-direction:column;align-items:flex-start;gap:10px}
  .footer-grid{grid-template-columns:1fr}
  .l-metric-block{padding:32px 24px}
}
@media(prefers-reduced-motion:reduce){
  .stage-card,.flow-path,.pulse-ring,.packet,.pipeline-step::before,.orb,.orb-rings,.t-row{animation:none!important}
}
`

const STATUS_STATES = [
  { mode: 'allow',      call: 'database.query',         signal: 'read-only query matches approved baseline',                        decision: 'ALLOW',      audit: 'allow event written with role, server, tool, and matched policy' },
  { mode: 'monitor',    call: 'crm.search_contacts',     signal: 'PII detected in response body',                                    decision: 'MONITOR',    audit: 'monitor event written and response scanner evidence attached' },
  { mode: 'quarantine', call: 'slack-mcp / export_channel', signal: 'external sharing added after baseline',                         decision: 'QUARANTINE', audit: 'quarantine event written with drift severity and review reason' },
]

export default function Landing() {
  const [statusIdx, setStatusIdx] = useState(0)
  const [activeTab, setActiveTab] = useState(0)

  useEffect(() => {
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return
    const id = window.setInterval(() => setStatusIdx(i => (i + 1) % STATUS_STATES.length), 3600)
    return () => clearInterval(id)
  }, [])

  const state = STATUS_STATES[statusIdx]

  return (
    <div className="landing">
      <style>{STYLES}</style>

      {/* NAV */}
      <nav className="l-nav">
        <a href="#top" className="l-nav-logo">Interlock</a>
        <ul className="l-nav-links">
          <li><a href="#layers">HOW IT WORKS</a></li>
          <li><a href="#partner">DESIGN PARTNER</a></li>
          <li><a href="#architecture">ARCHITECTURE</a></li>
          <li><a href="https://interlock-security.notion.site/Interlock-Runtime-Security-Gateway-for-AI-Agents-35a82dc0e7c380efb499dbef25046664" target="_blank" rel="noreferrer">DOCS</a></li>
          <li><a href="https://calendly.com/maazahmed1856/interlock-demo-15-min" target="_blank" rel="noreferrer">LIVE DEMO</a></li>
        </ul>
        <div className="l-nav-actions">
          <Link to="/dashboard" className="btn-nav-ghost">Dashboard</Link>
          <a href="https://calendly.com/maazahmed1856/interlock-demo-15-min" target="_blank" rel="noreferrer" className="btn-nav-red">REQUEST ACCESS</a>
        </div>
      </nav>

      {/* HERO */}
      <section className="l-hero" id="top">
        <div className="l-hero-bg" />
        <div className="l-hero-grain" />
        <div className="l-hero-content">
          <h1>Runtime Security for <em>MCP Agents</em></h1>
          <p className="l-hero-sub">Baseline MCP tools, detect risky drift, enforce role-aware policy, scan responses, and audit every gateway decision across your agent stack.</p>
          <div className="l-hero-actions">
            <a href="https://calendly.com/maazahmed1856/interlock-demo-15-min" target="_blank" rel="noreferrer" className="btn-red-hero">REQUEST ACCESS</a>
            <a href="https://interlock-security.notion.site/Interlock-Runtime-Security-Gateway-for-AI-Agents-35a82dc0e7c380efb499dbef25046664" target="_blank" rel="noreferrer" className="btn-docs-hero">DOCS</a>
          </div>
          <div className="l-hero-trusted">
            <p>Built for teams deploying AI agents with MCP tool access</p>
            <div className="trusted-row">
              <span className="trusted-name">MCP Servers</span>
              <span className="trusted-name">FastAPI</span>
              <span className="trusted-name">Self-hosted</span>
              <span className="trusted-name">Shadow Mode</span>
            </div>
          </div>
        </div>
      </section>

      {/* ARCH SPLIT */}
      <div className="arch-container">
        <div className="arch-left" style={{ position: 'relative' }}>
          <div className="orb"><div className="orb-rings" /></div>
          <h2>What is<br />Interlock?</h2>
        </div>
        <div className="arch-right">
          <p>Interlock is an MCP security control plane for teams using multiple MCP servers and agent tools together. It gives operators one place for tool baselines, drift detection, role-aware policy, response scanning, and structured audit logs across heterogeneous servers. This is not a replacement for server RBAC; it is the centralized policy, audit, and output-scanning layer in front of many MCP servers.</p>
        </div>
      </div>

      {/* FLOW SECTION */}
      <section className="l-flow-section" id="architecture">
        <div className="l-flow-title">
          <h2>The Security Layer<br />Between AI and Action</h2>
          <p>Every MCP tool call passes through Interlock — classified, checked against policy, scanned, and logged before reaching upstream tools.</p>
        </div>
        <div className="flow-diagram-wrap">
          <div className="active-flow-canvas" aria-label="Animated MCP security architecture flow">
            <svg viewBox="0 0 1120 560" role="img" preserveAspectRatio="xMidYMid meet">
              <defs>
                <linearGradient id="gatewayGradient" x1="0" x2="1" y1="0" y2="1">
                  <stop offset="0%" stopColor="#00e5c8" stopOpacity=".24"/>
                  <stop offset="55%" stopColor="#e8182c" stopOpacity=".18"/>
                  <stop offset="100%" stopColor="#7c3aed" stopOpacity=".26"/>
                </linearGradient>
                <filter id="blurCyan" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="8"/></filter>
                <filter id="blurLime" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="7"/></filter>
                <filter id="blurOrange" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="8"/></filter>
                <filter id="blurPurple" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="7"/></filter>
              </defs>

              {/* Connector lines */}
              <path className="flow-path primary"    d="M214 252 C270 252 310 252 350 252"/>
              <path className="flow-path allow"      d="M770 252 C836 252 880 182 930 182"/>
              <path className="flow-path quarantine" d="M770 280 C840 280 882 390 930 406"/>
              <path className="flow-path audit"      d="M535 360 C548 398 605 448 640 472"/>

              {/* AI Agent */}
              <g className="flow-node agent-node">
                <rect fill="none" stroke="rgba(46,168,255,.80)" strokeWidth="3" x="32" y="190" width="190" height="124" opacity="0.45" filter="url(#blurCyan)"/>
                <rect className="node-box hot" x="40" y="198" width="174" height="108"/>
                <circle className="pulse-ring" cx="70" cy="228" r="18"/>
                <text className="node-kicker" x="66" y="228">AI</text>
                <text className="node-title"  x="66" y="258">AI Agent</text>
                <text className="node-small"  x="66" y="278">tool call requested</text>
              </g>

              {/* MCP Servers */}
              <g className="flow-node mcp-node">
                <rect fill="none" stroke="rgba(200,240,0,.75)" strokeWidth="3" x="922" y="116" width="176" height="132" opacity="0.38" filter="url(#blurLime)"/>
                <rect className="node-box hot" x="930" y="124" width="160" height="116"/>
                <text className="node-kicker" x="960" y="158">UPSTREAM</text>
                <text className="node-title"  x="960" y="188">MCP Servers</text>
                <text className="node-small"  x="960" y="212">Slack · DB · Files</text>
              </g>

              {/* Quarantine */}
              <g className="flow-node quarantine-node">
                <rect fill="none" stroke="rgba(255,107,53,.80)" strokeWidth="3" x="922" y="340" width="176" height="132" opacity="0.45" filter="url(#blurOrange)"/>
                <rect className="node-box warn" x="930" y="348" width="160" height="116"/>
                <circle className="pulse-ring warn" cx="960" cy="378" r="18"/>
                <text className="node-kicker" x="960" y="382">REVIEW</text>
                <text className="node-title"  x="960" y="412">Quarantine</text>
                <text className="node-small"  x="960" y="436">operator decision</text>
              </g>

              {/* Audit Log */}
              <g className="flow-node audit-node">
                <rect fill="none" stroke="rgba(124,58,237,.78)" strokeWidth="3" x="632" y="418" width="196" height="108" opacity="0.45" filter="url(#blurPurple)"/>
                <rect className="node-box" x="640" y="426" width="180" height="92"/>
                <circle className="pulse-ring audit" cx="672" cy="456" r="17"/>
                <text className="node-kicker" x="668" y="460">LOG</text>
                <text className="node-title"  x="668" y="488">Audit Log</text>
              </g>

              {/* Interlock Gateway */}
              <rect className="gateway-shell" x="350" y="92" width="420" height="280" rx="2" fill="url(#gatewayGradient)"/>
              <text className="gateway-label" x="382" y="132">Interlock Gateway</text>
              <text className="gateway-sub"   x="382" y="156">BASELINE · POLICY · SCAN · AUDIT</text>
              <g className="stage-card stage-1"><rect x="382" y="188" width="142" height="52"/><circle className="stage-dot" cx="406" cy="214" r="5"/><text x="422" y="219">Discover</text></g>
              <g className="stage-card stage-2"><rect x="548" y="188" width="142" height="52"/><circle className="stage-dot" cx="572" cy="214" r="5"/><text x="588" y="219">Baseline</text></g>
              <g className="stage-card stage-3"><rect x="382" y="256" width="142" height="52"/><circle className="stage-dot" cx="406" cy="282" r="5"/><text x="422" y="287">Policy</text></g>
              <g className="stage-card stage-4"><rect x="548" y="256" width="142" height="52"/><circle className="stage-dot" cx="572" cy="282" r="5"/><text x="588" y="287">Scan</text></g>
              <g className="stage-card stage-5"><rect x="464" y="318" width="142" height="42"/><circle className="stage-dot" cx="488" cy="339" r="5"/><text x="504" y="344">Audit</text></g>

              {/* Packets */}
              <circle className="packet" r="6" fill="#00e5c8">
                <animateMotion dur="5.8s" repeatCount="indefinite" path="M214 252 C270 252 310 252 350 252"/>
              </circle>
              <circle className="packet allow" r="5">
                <animateMotion dur="5.8s" begin="1.85s" repeatCount="indefinite" path="M770 252 C836 252 880 182 930 182"/>
              </circle>
              <circle className="packet quarantine" r="5.5">
                <animateMotion dur="5.8s" begin="3.55s" repeatCount="indefinite" path="M770 280 C840 280 882 390 930 406"/>
              </circle>
              <circle className="packet audit" r="5">
                <animateMotion dur="5.8s" begin="4.35s" repeatCount="indefinite" path="M535 360 C548 398 605 448 640 472"/>
              </circle>
            </svg>
          </div>

          <aside className="active-status-panel">
            <div className="status-panel-top">
              <div className="status-panel-title">Runtime Decision</div>
              <div className="status-live">live flow</div>
            </div>
            <div className="l-status-card">
              <div className="l-status-label">Current call</div>
              <div className="l-status-value">{state.call}</div>
            </div>
            <div className="l-status-card">
              <div className="l-status-label">Signal</div>
              <div className="l-status-value">{state.signal}</div>
            </div>
            <div className="l-status-card">
              <div className="l-status-label">Decision</div>
              <div className={`l-status-decision ${state.mode}`}>{state.decision}</div>
            </div>
            <div className="l-status-card">
              <div className="l-status-label">Audit</div>
              <div className="l-status-value">{state.audit}</div>
            </div>
            <div className="status-timeline">
              <div className="status-step"><div className="status-step-dot">1</div><div>Normalize metadata and compare against trusted baseline.</div></div>
              <div className="status-step"><div className="status-step-dot">2</div><div>Apply role-aware policy before execution.</div></div>
              <div className="status-step"><div className="status-step-dot">3</div><div>Record the decision for review and audit evidence.</div></div>
            </div>
          </aside>
        </div>
      </section>

      {/* LAYERS */}
      <section className="l-layers-section" id="layers">
        <div className="l-layers-header">
          <h2>Layered Runtime Inspection</h2>
          <p>Every request can run layered checks across fingerprints, rules, patterns, LLM judgment, and custom policy.</p>
        </div>
        <div className="layers-pipeline">
          {[
            { num: 'L0', name: 'Learned Memory', desc: 'Fingerprint match against known threat patterns from prior sessions', tag: '0–2ms', cls: 'tag-cyan' },
            { num: 'L1', name: 'Rule Engine', desc: 'Regex, unicode bypass, leetspeak, base64 encoding, PII patterns', tag: 'FAST', cls: 'tag-lime' },
            { num: 'L2', name: 'Pattern Matcher', desc: '80+ weighted threat signals across injection and exfiltration categories', tag: '80+ SIGNALS', cls: 'tag-cyan' },
            { num: 'L3', name: 'LLM Judge', desc: 'Groq-powered semantic analysis for novel and sophisticated attacks', tag: 'AI LAYER', cls: 'tag-red' },
            { num: 'CP', name: 'Custom Policy', desc: 'Per-API-key rules, role-based enforcement, ALLOW / BLOCK / MONITOR / QUARANTINE', tag: 'ENFORCE', cls: 'tag-lime' },
          ].map(s => (
            <div key={s.num} className="pipeline-step">
              <div className="step-num">{s.num}</div>
              <div className="step-name">{s.name}</div>
              <div className="step-desc">{s.desc}</div>
              <span className={`step-tag ${s.cls}`}>{s.tag}</span>
            </div>
          ))}
        </div>
      </section>

      {/* SPLIT — Policy Enforcement */}
      <div className="split-section">
        <div className="split-left" style={{ background: 'linear-gradient(135deg,#0a0010,#1a0040,#3d0080)' }}>
          <div style={{ marginBottom: 40, position: 'relative', zIndex: 1 }}>
            <svg width="680" height="330" viewBox="0 0 680 330" style={{ width: '100%', maxWidth: 680, height: 'auto', display: 'block' }}>
              <defs>
                <marker id="pd-red-tip" markerWidth="9" markerHeight="9" refX="8" refY="4.5" orient="auto"><path d="M0,0 L0,9 L9,4.5 z" fill="#E14B32" fillOpacity=".95"/></marker>
                <marker id="pd-dim-tip" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L0,8 L8,4 z" fill="#00C8B4" fillOpacity=".42"/></marker>
                <marker id="pd-purple-tip" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L0,8 L8,4 z" fill="#9650F0" fillOpacity=".68"/></marker>
                <filter id="pd-soft-purple" x="-35%" y="-35%" width="170%" height="170%"><feGaussianBlur stdDeviation="7" result="blur"/><feFlood floodColor="#9650F0" floodOpacity=".22"/><feComposite in2="blur" operator="in"/><feMerge><feMergeNode/><feMergeNode in="SourceGraphic"/></feMerge></filter>
                <filter id="pd-soft-red" x="-35%" y="-35%" width="170%" height="170%"><feGaussianBlur stdDeviation="5" result="blur"/><feFlood floodColor="#E14B32" floodOpacity=".18"/><feComposite in2="blur" operator="in"/><feMerge><feMergeNode/><feMergeNode in="SourceGraphic"/></feMerge></filter>
              </defs>
              <rect x="8" y="8" width="664" height="314" rx="10" fill="#060608" fillOpacity=".10" stroke="#F5F0E8" strokeOpacity=".06"/>
              <rect x="24" y="124" width="138" height="84" rx="5" fill="#060608" fillOpacity=".36" stroke="#F5F0E8" strokeOpacity=".34" strokeWidth="1.3"/>
              <text x="93" y="155" textAnchor="middle" fill="#F5F0E8" fillOpacity=".88" fontFamily="DM Mono,monospace" fontSize="14">AGENT</text>
              <text x="93" y="178" textAnchor="middle" fill="#F5F0E8" fillOpacity=".58" fontFamily="DM Mono,monospace" fontSize="13">payment-v2</text>
              <line x1="162" y1="166" x2="250" y2="166" stroke="#E14B32" strokeOpacity=".92" strokeWidth="1.9" strokeDasharray="6,4" markerEnd="url(#pd-red-tip)"><animate attributeName="stroke-dashoffset" from="20" to="0" dur=".95s" repeatCount="indefinite"/></line>
              <rect x="178" y="126" width="58" height="24" rx="12" fill="#060608" fillOpacity=".68" stroke="#E14B32" strokeOpacity=".42" filter="url(#pd-soft-red)"/>
              <text x="207" y="143" textAnchor="middle" fill="#EB5035" fillOpacity="1" fontFamily="DM Mono,monospace" fontSize="13" fontWeight="700">BLOCKED</text>
              <text x="207" y="194" textAnchor="middle" fill="#F06D55" fillOpacity=".88" fontFamily="DM Mono,monospace" fontSize="13">role denied</text>
              <rect x="250" y="92" width="184" height="148" rx="7" fill="#07040E" fillOpacity=".88" stroke="#9650F0" strokeOpacity=".84" strokeWidth="1.7" filter="url(#pd-soft-purple)"><animate attributeName="stroke-opacity" values=".70;.96;.70" dur="2.8s" repeatCount="indefinite"/></rect>
              <text x="342" y="150" textAnchor="middle" fill="#FFFFFF" fillOpacity=".98" fontFamily="Geist,Inter,sans-serif" fontSize="17" fontWeight="750">Interlock</text>
              <text x="342" y="177" textAnchor="middle" fill="#D9CFFF" fillOpacity=".88" fontFamily="DM Mono,monospace" fontSize="14">Policy Check</text>
              <path d="M434,130 C466,130 480,74 510,74" fill="none" stroke="#00C8B4" strokeOpacity=".42" strokeWidth="1.4" strokeDasharray="6,4" markerEnd="url(#pd-dim-tip)"><animate attributeName="stroke-dashoffset" from="0" to="20" dur="2.2s" repeatCount="indefinite"/></path>
              <line x1="434" y1="166" x2="510" y2="166" stroke="#00C8B4" strokeOpacity=".38" strokeWidth="1.4" strokeDasharray="6,4" markerEnd="url(#pd-dim-tip)"><animate attributeName="stroke-dashoffset" from="0" to="20" dur="2.5s" repeatCount="indefinite"/></line>
              <path d="M434,202 C466,202 480,258 510,258" fill="none" stroke="#00C8B4" strokeOpacity=".36" strokeWidth="1.4" strokeDasharray="6,4" markerEnd="url(#pd-dim-tip)"><animate attributeName="stroke-dashoffset" from="0" to="20" dur="2.0s" repeatCount="indefinite"/></path>
              <g opacity=".72">
                <rect x="510" y="52" width="118" height="44" rx="4" fill="#060608" fillOpacity=".34" stroke="#F5F0E8" strokeOpacity=".26" strokeWidth="1.1"/>
                <text x="569" y="80" textAnchor="middle" fill="#F5F0E8" fillOpacity=".72" fontFamily="DM Mono,monospace" fontSize="14">Stripe</text>
                <rect x="510" y="144" width="118" height="44" rx="4" fill="#060608" fillOpacity=".34" stroke="#F5F0E8" strokeOpacity=".26" strokeWidth="1.1"/>
                <text x="569" y="172" textAnchor="middle" fill="#F5F0E8" fillOpacity=".72" fontFamily="DM Mono,monospace" fontSize="14">DB</text>
                <rect x="510" y="236" width="118" height="44" rx="4" fill="#060608" fillOpacity=".34" stroke="#F5F0E8" strokeOpacity=".26" strokeWidth="1.1"/>
                <text x="569" y="264" textAnchor="middle" fill="#F5F0E8" fillOpacity=".72" fontFamily="DM Mono,monospace" fontSize="14">Mail</text>
              </g>
              <text x="569" y="304" textAnchor="middle" fill="#F5F0E8" fillOpacity=".48" fontFamily="DM Mono,monospace" fontSize="13">tools not reached</text>
              <line x1="342" y1="240" x2="342" y2="274" stroke="#9650F0" strokeOpacity=".62" strokeWidth="1.4" strokeDasharray="4,4" markerEnd="url(#pd-purple-tip)"><animate attributeName="stroke-dashoffset" from="0" to="14" dur="1.6s" repeatCount="indefinite"/></line>
              <rect x="250" y="278" width="184" height="42" rx="5" fill="#060608" fillOpacity=".58" stroke="#9650F0" strokeOpacity=".62" strokeWidth="1.2"><animate attributeName="stroke-opacity" values=".55;.86;.55" dur="3.2s" repeatCount="indefinite"/></rect>
              <text x="342" y="304" textAnchor="middle" fill="#D2C0FF" fillOpacity=".92" fontFamily="DM Mono,monospace" fontSize="14">Audit event</text>
            </svg>
          </div>
          <div style={{ position: 'relative', zIndex: 1 }}>
            <div className="split-label">PRE-EXECUTION POLICY</div>
            <div className="split-title">Policy Enforcement<br />Before Execution</div>
            <p className="split-body">Interlock intercepts every tool call before it fires. Role-based policies determine whether to allow, monitor, quarantine, or block — based on the request content, user role, and tool sensitivity.</p>
            <a href="https://interlock-security.notion.site/Interlock-Runtime-Security-Gateway-for-AI-Agents-35a82dc0e7c380efb499dbef25046664" target="_blank" rel="noreferrer" className="btn-outline">READ MORE</a>
          </div>
        </div>
        <div className="split-right">
          <div className="code-display">
            <div className="code-tabs">
              {['Python', 'JavaScript', '</> API'].map((t, i) => (
                <button key={t} className={`code-tab${activeTab === i ? ' active' : ''}`} onClick={() => setActiveTab(i)}>{t}</button>
              ))}
            </div>
            <div className="code-body">
              {activeTab === 0 && <>
                <span className="cm"># Before Interlock — direct to LLM</span><br/>
                <span className="ck">client</span> = <span className="cf">OpenAI</span>(<br/>
                &nbsp;&nbsp;<span className="ck">base_url</span>=<span className="cs">"https://api.openai.com/v1"</span><br/>
                )<br/><br/>
                <span className="cm"># After Interlock — one line change</span><br/>
                <span className="ck">client</span> = <span className="cf">OpenAI</span>(<br/>
                &nbsp;&nbsp;<span className="ck">base_url</span>=<span className="cs">"https://interlock.onrender.com/v1"</span>,<br/>
                &nbsp;&nbsp;<span className="ck">default_headers</span>={'{'}<br/>
                &nbsp;&nbsp;&nbsp;&nbsp;<span className="cs">"x-api-key"</span>: <span className="cf">os.environ</span>[<span className="cs">"INTERLOCK_KEY"</span>]<br/>
                &nbsp;&nbsp;{'}'}<br/>
                )<br/><br/>
                <span className="cm"># Every tool call now inspected + logged</span><br/>
                <span className="cm"># No agent logic changes required</span>
              </>}
              {activeTab === 1 && <>
                <span className="cm">// Before Interlock</span><br/>
                <span className="ck">const</span> client = <span className="cf">new</span> <span className="cf">OpenAI</span>({'{'}<br/>
                &nbsp;&nbsp;<span className="ck">baseURL</span>: <span className="cs">"https://api.openai.com/v1"</span><br/>
                {'}'});<br/><br/>
                <span className="cm">// After Interlock — one line change</span><br/>
                <span className="ck">const</span> client = <span className="cf">new</span> <span className="cf">OpenAI</span>({'{'}<br/>
                &nbsp;&nbsp;<span className="ck">baseURL</span>: <span className="cs">"https://interlock.onrender.com/v1"</span>,<br/>
                &nbsp;&nbsp;<span className="ck">defaultHeaders</span>: {'{'}<br/>
                &nbsp;&nbsp;&nbsp;&nbsp;<span className="cs">"x-api-key"</span>: process.<span className="cf">env</span>.<span className="cn">INTERLOCK_KEY</span><br/>
                &nbsp;&nbsp;{'}'}<br/>
                {'}'});
              </>}
              {activeTab === 2 && <>
                <span className="cm"># Direct API call</span><br/>
                <span className="cf">POST</span> <span className="cs">https://interlock.onrender.com/scan</span><br/>
                <span className="ck">x-api-key</span>: <span className="cn">your-key</span><br/><br/>
                {'{'}<br/>
                &nbsp;&nbsp;<span className="cs">"prompt"</span>: <span className="cs">"your content"</span><br/>
                {'}'}<br/><br/>
                <span className="cm"># Returns: is_threat, threat_level,</span><br/>
                <span className="cm"># reason, confidence, layer_caught</span>
              </>}
            </div>
          </div>
        </div>
      </div>

      {/* SPLIT — Observability */}
      <div className="split-section">
        <div className="split-right" style={{ order: -1, borderLeft: 'none', borderRight: '1px solid rgba(245,240,232,.08)' }}>
          <div className="audit-terminal">
            <div className="terminal-bar">
              <div className="t-dot t-red"/><div className="t-dot t-yellow"/><div className="t-dot t-green"/>
              <div className="terminal-title">INTERLOCK LIVE AUDIT — agent: payment-processor-v2</div>
            </div>
            <div className="terminal-body">
              {[
                { time: '16:54:01', action: 'tool:stripe.charge — amount=847.00, user=u_9a2f', cls: 'b-allow', label: 'ALLOW' },
                { time: '16:54:03', action: 'tool:db.query — PII pattern detected (email)', cls: 'b-monitor', label: 'MONITOR' },
                { time: '16:54:07', action: 'tool:send_email — body injection L2 score=0.91', cls: 'b-block', label: 'BLOCK' },
                { time: '16:54:09', action: 'tool:slack.export_channel — external sharing added post-baseline', cls: 'b-quarantine', label: 'QUARANTINE' },
                { time: '16:54:12', action: 'tool:db.query — schema:users, cols: id,name', cls: 'b-allow', label: 'ALLOW' },
                { time: '16:54:15', action: 'tool:send_email — drift detected post-approval', cls: 'b-block', label: 'BLOCK' },
              ].map((r, i) => (
                <div key={i} className="t-row">
                  <div className="t-time">{r.time}</div>
                  <div className="t-action">{r.action}</div>
                  <div className={`t-badge ${r.cls}`}>{r.label}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
        <div className="split-left" style={{ background: 'linear-gradient(135deg,#001a14,#003328,#006650)' }}>
          <div style={{ position: 'relative', zIndex: 1 }}>
            <div className="split-label">OBSERVABILITY</div>
            <div className="split-title">Every Decision,<br />Fully Auditable</div>
            <p className="split-body">Real-time feed of every allow, block, monitor, and quarantine decision. Full decision context stored. Export to Datadog, Splunk, Elastic, Slack, PagerDuty, or webhook. Built for teams that need clear evidence for security review, compliance workflows, and incident response.</p>
            <a href="https://interlock-security.notion.site/Interlock-Runtime-Security-Gateway-for-AI-Agents-35a82dc0e7c380efb499dbef25046664" target="_blank" rel="noreferrer" className="btn-outline">READ MORE</a>
          </div>
        </div>
      </div>

      {/* COLOR SPLIT */}
      <div className="color-split">
        <div className="cs-block cs-cyan"><div className="cs-icon">🔍</div><h3>Tool Drift Detection</h3><p>Interlock baselines every MCP tool at discovery time. If schema, capability, or metadata changes later, the drift is classified and can be monitored, denied, or quarantined before execution.</p></div>
        <div className="cs-block cs-lime"><div className="cs-icon">📋</div><h3>Deployment Flexibility</h3><p>Deploy in the cloud, your VPC, on-premises, or fully air-gapped. You control where your data lives and how it's secured. No vendor lock-in.</p></div>
        <div className="cs-block cs-red"><div className="cs-icon">🛡️</div><h3>Response Scanning</h3><p>Tool and model responses are scanned for injected instructions, secrets, PII, and exfiltration patterns before they are forwarded downstream.</p></div>
        <div className="cs-block cs-purple"><div className="cs-icon">⚡</div><h3>Configurable Fail Mode</h3><p>Choose fail-open, fail-closed, or fail-open-safe per environment. If Interlock is unreachable, requests follow your configured policy instead of an implicit default.</p></div>
      </div>

      {/* METRICS */}
      <div className="l-metrics-strip">
        <div className="l-metric-block"><div className="l-metric-num"><span>&lt;1</span>s</div><div className="l-metric-desc">Policy evaluation and stored drift/provenance check per call</div></div>
        <div className="l-metric-block"><div className="l-metric-num"><span>6</span></div><div className="l-metric-desc">Security stages per MCP call — trust, policy, inspect, RBAC, scan, audit</div></div>
        <div className="l-metric-block"><div className="l-metric-num">80<span>+</span></div><div className="l-metric-desc">Weighted threat signals in the pattern matcher</div></div>
        <div className="l-metric-block"><div className="l-metric-num"><span>0</span></div><div className="l-metric-desc">Agent logic changes needed — one base_url swap</div></div>
      </div>

      {/* PRICING */}
      <section className="l-pricing-section" id="partner">
        <h2>Design Partner Program</h2>
        <p>Pre-release. Working with a small group of teams for honest feedback.</p>
        <div className="pricing-grid">
          <div className="price-block">
            <div className="price-tier">Builder</div>
            <div className="price-amount">Free</div>
            <div className="price-period">shadow mode · evaluate risk</div>
            <ul className="price-features">
              <li>Shadow mode — log threats, block nothing</li>
              <li>Limited audit log access pipeline</li>
              <li>Structured event review</li>
              <li>Email support</li>
              <li className="off">Custom policies</li>
              <li className="off">Webhook export</li>
              <li className="off">Dedicated support terms</li>
            </ul>
            <a href="mailto:maazahmed1856@gmail.com" className="btn-price">APPLY VIA EMAIL</a>
          </div>
          <div className="price-block featured">
            <div className="price-tier">Design Partner</div>
            <div className="price-amount">Apply</div>
            <div className="price-period">shape the roadmap · early access</div>
            <ul className="price-features">
              <li>Full enforcement + all modes</li>
              <li>Direct access to founder</li>
              <li>Structured audit log access</li>
              <li>Roadmap input + early features</li>
              <li>Custom policy configuration</li>
              <li>Priority support + onboarding call</li>
              <li className="off">Dedicated support terms</li>
            </ul>
            <a href="https://calendly.com/maazahmed1856/interlock-demo-15-min" target="_blank" rel="noreferrer" className="btn-price red-btn">BOOK INTRO CALL</a>
          </div>
          <div className="price-block">
            <div className="price-tier">Enterprise</div>
            <div className="price-amount">Custom</div>
            <div className="price-period">VPC / on-prem · regulated teams</div>
            <ul className="price-features">
              <li>On-premises or VPC deployment</li>
              <li>Custom detection signals</li>
              <li>Full log retention + export</li>
              <li>Role-based policy mgmt</li>
              <li>SIEM + compliance workflows</li>
              <li>Scoped to your compliance needs</li>
            </ul>
            <a href="mailto:maazahmed1856@gmail.com" className="btn-price">GET IN TOUCH</a>
          </div>
        </div>
      </section>

      {/* FINAL CTA */}
      <div className="final-cta">
        <div className="cta-left">
          <h2>Get early access to Interlock and start securing your agents.</h2>
          <div className="cta-actions">
            <a href="https://calendly.com/maazahmed1856/interlock-demo-15-min" target="_blank" rel="noreferrer" className="btn-cta-black">BOOK A DEMO</a>
            <a href="https://interlock-security.notion.site/Interlock-Runtime-Security-Gateway-for-AI-Agents-35a82dc0e7c380efb499dbef25046664" target="_blank" rel="noreferrer" className="btn-cta-docs">DOCS</a>
          </div>
        </div>
        <div className="cta-right">
          <h2>Your agents are gaining tool access. <em>Can your security explain every decision?</em></h2>
          <a href="https://calendly.com/maazahmed1856/interlock-demo-15-min" target="_blank" rel="noreferrer" className="btn-cta-white">BOOK A DEMO</a>
        </div>
      </div>

      {/* FOOTER */}
      <footer className="l-footer">
        <div className="footer-grid">
          <div className="footer-brand">
            <div className="footer-brand-name">Interlock</div>
            <p>MCP security control plane for tool baselines, drift detection, policy enforcement, response scanning, and audit evidence.</p>
          </div>
          <div className="footer-col">
            <h5>Product</h5>
            <a href="#layers">How it works</a>
            <a href="#partner">Design Partner</a>
            <a href="https://calendly.com/maazahmed1856/interlock-demo-15-min" target="_blank" rel="noreferrer">Pilot Roadmap</a>
          </div>
          <div className="footer-col">
            <h5>Developers</h5>
            <a href="https://interlock-security.notion.site/Interlock-Runtime-Security-Gateway-for-AI-Agents-35a82dc0e7c380efb499dbef25046664" target="_blank" rel="noreferrer">Documentation</a>
            <a href="https://interlock.onrender.com/docs" target="_blank" rel="noreferrer">API Reference</a>
            <a href="https://github.com/MaazAhmed47/Interlock" target="_blank" rel="noreferrer">GitHub</a>
          </div>
          <div className="footer-col">
            <h5>Company</h5>
            <a href="https://interlock-security.notion.site/Interlock-Runtime-Security-Gateway-for-AI-Agents-35a82dc0e7c380efb499dbef25046664" target="_blank" rel="noreferrer">Spec Sheet</a>
            <a href="mailto:maazahmed1856@gmail.com">Contact</a>
          </div>
          <div className="footer-col">
            <h5>Legal</h5>
            <a href="mailto:maazahmed1856@gmail.com">Email</a>
            <a href="https://github.com/MaazAhmed47/Interlock" target="_blank" rel="noreferrer">GitHub</a>
          </div>
        </div>
        <div className="footer-bottom">
          <span>© 2026 Interlock</span>
          <span>
            <a href="mailto:maazahmed1856@gmail.com" style={{ color: 'inherit' }}>maazahmed1856@gmail.com</a>
            &nbsp;·&nbsp;
            <a href="https://github.com/MaazAhmed47/Interlock" target="_blank" rel="noreferrer" style={{ color: 'inherit' }}>GITHUB</a>
          </span>
        </div>
      </footer>
    </div>
  )
}
