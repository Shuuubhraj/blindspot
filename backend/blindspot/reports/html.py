"""Self-contained HTML report generator.

The report embeds all CSS/JS, makes no external network requests, and
escapes every untrusted value (Jinja2 autoescape). It opens locally with
no backend required.
"""

from __future__ import annotations

import html as _html

from jinja2 import Environment, select_autoescape

from .common import build_report_data

_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Blindspot Assessment - {{ d.file_name }}</title>
<style>
  :root { --bg:#0f141b; --panel:#171e27; --ink:#e8edf3; --mut:#9aa7b5;
          --crit:#e5484d; --high:#f76b15; --med:#f5a524; --low:#3e9bff; --info:#8b949e;
          --line:#26303c; }
  * { box-sizing:border-box; }
  body { margin:0; font-family: ui-sans-serif, system-ui, "Segoe UI", Roboto, sans-serif;
         background:var(--bg); color:var(--ink); line-height:1.55; }
  .wrap { max-width:1080px; margin:0 auto; padding:32px 24px 64px; }
  header.cover { border:1px solid var(--line); border-radius:12px; padding:36px;
                 background:linear-gradient(135deg,#16202c,#10161d); margin-bottom:28px; }
  header.cover h1 { margin:0 0 4px; font-size:30px; letter-spacing:.5px; }
  header.cover .tag { color:var(--mut); font-size:14px; }
  .meta-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr));
               gap:12px; margin-top:20px; }
  .meta-grid .cell { background:var(--panel); border:1px solid var(--line);
                     border-radius:8px; padding:10px 14px; }
  .meta-grid .k { font-size:11px; text-transform:uppercase; color:var(--mut);
                  letter-spacing:.08em; }
  .meta-grid .v { font-size:14px; word-break:break-all; }
  h2 { font-size:20px; margin:36px 0 12px; padding-bottom:8px;
       border-bottom:1px solid var(--line); }
  h3 { font-size:16px; margin:22px 0 8px; }
  p, li { font-size:14px; }
  .mut { color:var(--mut); }
  .sev-cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; }
  .sev-card { border:1px solid var(--line); border-radius:10px; padding:14px;
              background:var(--panel); }
  .sev-card .n { font-size:30px; font-weight:700; }
  .sev-card .l { font-size:12px; text-transform:uppercase; letter-spacing:.08em; color:var(--mut); }
  .bar { height:8px; border-radius:4px; background:#232d38; margin-top:8px; overflow:hidden; }
  .bar > div { height:100%; border-radius:4px; }
  .crit{color:var(--crit)} .high{color:var(--high)} .med{color:var(--med)}
  .low{color:var(--low)} .info{color:var(--info)}
  .bg-crit{background:var(--crit)} .bg-high{background:var(--high)} .bg-med{background:var(--med)}
  .bg-low{background:var(--low)} .bg-info{background:var(--info)}
  table { width:100%; border-collapse:collapse; font-size:13px; margin:12px 0; }
  th, td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); vertical-align:top; }
  th { color:var(--mut); font-size:11px; text-transform:uppercase; letter-spacing:.06em; }
  .finding { border:1px solid var(--line); border-radius:10px; background:var(--panel);
             margin:16px 0; overflow:hidden; }
  .finding-head { padding:14px 18px; border-bottom:1px solid var(--line); }
  .finding-head h3 { margin:0 0 6px; font-size:16px; }
  .finding-body { padding:6px 18px 16px; }
  .pill { display:inline-block; font-size:11px; font-weight:600; padding:2px 10px;
          border-radius:999px; margin-right:6px; text-transform:uppercase; letter-spacing:.05em;}
  .p-crit{background:#3a1416;color:#ff8a8e} .p-high{background:#3a1f10;color:#ffb37a}
  .p-med{background:#3a2c0e;color:#ffd37a} .p-low{background:#10283f;color:#7cc0ff}
  .p-info{background:#232d38;color:#aeb9c4}
  pre.code { background:#0b0f14; border:1px solid var(--line); border-radius:8px;
             padding:12px 14px; overflow-x:auto; font-size:12.5px; line-height:1.5;
             font-family: ui-monospace, SFMono-Regular, Menlo, monospace; white-space:pre-wrap;
             word-break:break-word; }
  .kv { display:grid; grid-template-columns:180px 1fr; gap:6px 12px; font-size:13px; margin:10px 0; }
  .kv .k { color:var(--mut); }
  .toc a { color:#7cc0ff; text-decoration:none; font-size:14px; }
  .toc li { margin:4px 0; }
  .warn { background:#2a1f08; border:1px solid #5a4413; border-radius:8px;
          padding:12px 16px; font-size:13px; margin:12px 0; }
  footer { margin-top:48px; color:var(--mut); font-size:12px; border-top:1px solid var(--line); padding-top:16px; }
  @media print {
    body { background:#fff; color:#111; }
    header.cover, .sev-card, .finding { background:#fff; border-color:#ccc; }
    pre.code { background:#f6f6f6; border-color:#ccc; }
    .finding { break-inside:avoid; }
    h2 { break-after:avoid; }
  }
</style>
</head>
<body>
<div class="wrap">

<header class="cover">
  <h1>Blindspot Security Assessment</h1>
  <div class="tag">Find what others miss. - Static APK security assessment report</div>
  <div class="tag" style="margin-top:6px">Developed by <a href="https://github.com/shuuubhraj" style="color:#7cc0ff">@shuuubhraj</a></div>
  <div class="meta-grid">
    <div class="cell"><div class="k">App name</div><div class="v">{{ d.app_name or d.file_name }}</div></div>
    <div class="cell"><div class="k">Package</div><div class="v">{{ d.package_name or "-" }}</div></div>
    <div class="cell"><div class="k">Version</div><div class="v">{{ d.version_name or "-" }} ({{ d.version_code or "-" }})</div></div>
    <div class="cell"><div class="k">SDK (min / target)</div><div class="v">{{ d.min_sdk or "-" }} / {{ d.target_sdk or "-" }}</div></div>
    <div class="cell"><div class="k">File</div><div class="v">{{ d.file_name }}</div></div>
    <div class="cell"><div class="k">Size</div><div class="v">{{ d.file_size_human }}</div></div>
    <div class="cell"><div class="k">SHA-256</div><div class="v" style="font-family:monospace;font-size:11px">{{ d.sha256 }}</div></div>
    <div class="cell"><div class="k">Assessed</div><div class="v">{{ d.finished_at or d.created_at }}</div></div>
    <div class="cell"><div class="k">Status</div><div class="v">{{ d.status }}</div></div>
  </div>
</header>

<h2>Executive summary</h2>
<p>
  Blindspot performed an automated <strong>static</strong> security assessment of
  <strong>{{ d.file_name }}</strong>
  ({% if d.package_name %}<strong>{{ d.package_name }}</strong>{% endif %}).
  The scan produced <strong>{{ d.total_findings }}</strong> finding(s):
  <span class="crit">{{ d.counts.critical }} critical</span>,
  <span class="high">{{ d.counts.high }} high</span>,
  <span class="med">{{ d.counts.medium }} medium</span>,
  <span class="low">{{ d.counts.low }} low</span>,
  <span class="info">{{ d.counts.informational }} informational</span>.
  {% if d.counts.critical or d.counts.high %}
  Critical and high findings should be triaged first; each includes evidence,
  impact, and remediation guidance below.
  {% else %}
  No critical or high severity findings were identified by the automated checks;
  review medium findings for defense-in-depth improvements.
  {% endif %}
</p>
{% if d.limitations %}
<div class="warn"><strong>Coverage notice:</strong> {{ d.limitations | length }} limitation(s) apply to this
assessment - see <a href="#limitations" style="color:#ffd37a">Limitations and exclusions</a>.</div>
{% endif %}

<h2>Contents</h2>
<ul class="toc">
  <li><a href="#scope">Scope and methodology</a></li>
  <li><a href="#metadata">APK metadata</a></li>
  <li><a href="#coverage">Scan coverage</a></li>
  <li><a href="#severity">Severity distribution</a></li>
  <li><a href="#owasp">OWASP Mobile Top 10 (2024) mapping</a></li>
  <li><a href="#ai-review">AI review</a></li>
  <li><a href="#findings">Detailed findings</a></li>
  <li><a href="#limitations">Limitations and exclusions</a></li>
</ul>

<h2 id="scope">Scope and methodology</h2>
<p>This assessment is <strong>static analysis only</strong>: the APK was unpacked and inspected without
executing it. No dynamic testing, network interaction, or backend testing was performed.</p>
<ul>
  <li>APK structure validation, SHA-256 hashing, safe extraction</li>
  <li>AndroidManifest.xml decoding and configuration analysis</li>
  <li>Permission, component-export and intent-filter analysis</li>
  <li>Decompiled-source review (where a decompiler was available)</li>
  <li>MobSFScan static analysis (when available)</li>
  <li>{{ d.rules_total }} custom Blindspot detection-rule executions across 7 categories</li>
  <li>Optional local-AI review (Ollama, on-device only - never a cloud service)</li>
</ul>
<p class="mut">Severity reflects potential impact if the issue is real and exploitable.
Confidence reflects how strongly the evidence supports the finding. The two are independent.</p>

<h2 id="metadata">APK metadata</h2>
<div class="kv">
  <div class="k">File name</div><div>{{ d.file_name }}</div>
  <div class="k">SHA-256</div><div style="font-family:monospace;font-size:12px">{{ d.sha256 }}</div>
  <div class="k">File size</div><div>{{ d.file_size_human }}</div>
  <div class="k">Package</div><div>{{ d.package_name or "-" }}</div>
  <div class="k">App name</div><div>{{ d.app_name or "-" }}</div>
  <div class="k">Version</div><div>{{ d.version_name or "-" }} ({{ d.version_code or "-" }})</div>
  <div class="k">SDK (min / target)</div><div>{{ d.min_sdk or "-" }} / {{ d.target_sdk or "-" }}</div>
</div>

<h2 id="coverage">Scan coverage</h2>
<table>
  <tr><th>Stage</th><th>Status</th><th>Duration</th><th>Note</th></tr>
  {% for st in d.stages %}
  <tr><td><code>{{ st.name }}</code></td><td>{{ st.status }}</td>
      <td>{{ st.duration_ms }} ms</td><td class="mut">{{ st.note or "-" }}</td></tr>
  {% endfor %}
</table>
<p>Rule executions by outcome:
{% for k, v in d.executions.items() %}<code>{{ k }}</code>: {{ v }} {% endfor %}</p>

<h2 id="severity">Severity distribution</h2>
<div class="sev-cards">
  {% for sev, label, cls in [("critical","Critical","crit"),("high","High","high"),("medium","Medium","med"),("low","Low","low"),("informational","Informational","info")] %}
  <div class="sev-card"><div class="n {{ cls }}">{{ d.counts[sev] }}</div><div class="l">{{ label }}</div>
    <div class="bar"><div class="bg-{{ cls }}" style="width:{{ (100 * d.counts[sev] / (d.total_findings or 1)) | round(1) }}%"></div></div>
  </div>
  {% endfor %}
</div>

<h2 id="owasp">OWASP Mobile Top 10 (2024) mapping</h2>
<table>
  <tr><th>Category</th><th>Name</th><th>Findings</th></tr>
  {% for code, name in d.owasp_names.items() %}
  <tr><td><code>{{ code }}</code></td><td>{{ name }}</td><td>{{ d.owasp_counts.get(code, 0) }}</td></tr>
  {% endfor %}
</table>
<p class="mut">OWASP categories are classification metadata, not severity scores.</p>

<h2 id="ai-review">AI review</h2>
{% if not d.ai_rows %}
<p class="mut">AI review was not run for this scan. Enable it in the scan configuration to get a
local on-device LLM second opinion (Ollama - never a cloud service).</p>
{% else %}
{% for a in d.ai_rows %}
<div class="kv">
  <div class="k">Model</div><div><code>{{ a.model }}</code></div>
  <div class="k">Status</div><div>{{ a.status }}</div>
  <div class="k">Files reviewed</div><div>{{ a.files_reviewed }}</div>
  <div class="k">Findings proposed / accepted</div><div>{{ a.findings_proposed }} / {{ a.findings_accepted }}</div>
  {% if a.error %}<div class="k">Note</div><div class="mut">{{ a.error }}</div>{% endif %}
</div>
{% endfor %}
<p class="mut">AI findings are hypotheses with hallucination controls: every AI-proposed finding is
validated against real code locations before it is kept, and findings the static engines
independently confirm are marked <em>ai-corroborated</em>. AI output never overrides a
static-engine result.</p>
{% if d.ai_findings %}
<table>
  <tr><th>#</th><th>Finding</th><th>Severity</th><th>Confidence</th><th>Location</th><th>Status</th></tr>
  {% for f in d.ai_findings %}
  <tr>
    <td>{{ loop.index }}</td>
    <td>{{ f.title }}</td>
    <td><span class="{{ f.severity[:4] if f.severity[:4] in ['crit','high','med','low','info'] else 'info' }}">{{ f.severity }}</span></td>
    <td>{{ f.confidence }}</td>
    <td style="font-family:monospace;font-size:12px">{{ f.file_path or "-" }}{% if f.line_start %}:{{ f.line_start }}{% endif %}</td>
    <td>{{ f.validation_status }}</td>
  </tr>
  {% endfor %}
</table>
{% else %}
<p class="mut">The AI review proposed no findings that survived validation for this scan.</p>
{% endif %}
{% endif %}

<h2 id="findings">Detailed findings</h2>
{% if not d.findings %}<p>No findings.</p>{% endif %}
{% for f in d.findings %}
<div class="finding">
  <div class="finding-head">
    <h3>{{ loop.index }}. {{ f.title }}</h3>
    <span class="pill p-{{ f.severity[:4] }}">{{ f.severity }}</span>
    <span class="pill p-info">confidence: {{ f.confidence }}</span>
    <span class="pill p-info">{{ f.validation_status }}</span>
    {% if f.review_status != "open" %}<span class="pill p-med">review: {{ f.review_status }}</span>{% endif %}
    <div class="mut" style="margin-top:6px;font-size:12px">
      {{ f.finding_id }} · rule <code>{{ f.rule_id }}</code> v{{ f.rule_version }} · engine: {{ f.engine }}
      {% if f.category %}· {{ f.category }}{% endif %}
    </div>
  </div>
  <div class="finding-body">
    <div class="kv">
      {% if f.file_path %}<div class="k">Location</div><div><code>{{ f.file_path }}</code>{% if f.line_start %} : lines {{ f.line_start }}{% if f.line_end and f.line_end != f.line_start %}–{{ f.line_end }}{% endif %}{% endif %}</div>{% endif %}
      {% if f.owasp %}<div class="k">OWASP</div><div>{{ f.owasp | join(", ") }}</div>{% endif %}
      {% if f.cwe %}<div class="k">CWE</div><div>{{ f.cwe | join(", ") }}</div>{% endif %}
    </div>
    <h3>Description</h3><p>{{ f.description }}</p>
    {% if f.snippet %}<h3>Evidence</h3><pre class="code">{{ f.snippet }}</pre>{% endif %}
    {% if f.severity_rationale %}<p class="mut"><strong>Severity rationale:</strong> {{ f.severity_rationale }}</p>{% endif %}
    {% if f.confidence_rationale %}<p class="mut"><strong>Confidence rationale:</strong> {{ f.confidence_rationale }}</p>{% endif %}
    {% if f.impact %}<h3>Impact</h3><p>{{ f.impact }}</p>{% endif %}
    {% if f.remediation %}<h3>Remediation</h3><p>{{ f.remediation }}</p>{% endif %}
    {% if f.provenance and f.provenance | length > 1 %}
    <p class="mut"><strong>Also detected by:</strong>
      {{ f.provenance[1:] | map(attribute="engine") | join(", ") }}</p>
    {% endif %}
    {% if f.review_note %}<p class="mut"><strong>Reviewer note:</strong> {{ f.review_note }}</p>{% endif %}
  </div>
</div>
{% endfor %}

<h2 id="limitations">Limitations and exclusions</h2>
<ul>
  <li>Static analysis only - no runtime, network, or backend testing was performed.</li>
  <li>Findings marked <em>heuristic</em> or <em>ai-unverified</em> require manual confirmation.</li>
  <li>Absence of a finding is not proof of absence of the vulnerability.</li>
  {% for lim in d.limitations %}<li>{{ lim }}</li>{% endfor %}
  {% if d.errors %}{% for e in d.errors %}<li class="mut">Tool error: {{ e }}</li>{% endfor %}{% endif %}
</ul>

<footer>
  Generated by Blindspot Security Console - local-first Android APK assessment.
  Developed by <a href="https://github.com/shuuubhraj" style="color:#7cc0ff">@shuuubhraj</a>.<br>
  Report generated {{ d.finished_at or d.created_at }} · scan {{ d.scan_id }}.
  Findings are point-in-time static observations for authorized assessment use.
</footer>

</div>
</body>
</html>
"""

_env = Environment(autoescape=select_autoescape(["html", "xml"]))


def render_html(scan_id: str) -> str | None:
    data = build_report_data(scan_id)
    if data is None:
        return None
    return _env.from_string(_TEMPLATE).render(d=data)


def _esc(text: str) -> str:
    return _html.escape(text or "")
