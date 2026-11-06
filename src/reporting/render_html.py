"""Static escaped HTML with embedded CSS; no scripts or remote assets."""
from html import escape
from .render_markdown import sections, number

CSS = '''body{font:16px/1.55 system-ui,sans-serif;color:#203047;background:#f1f4f8;margin:0}
main{max-width:1240px;margin:auto;padding:32px}h1{font-size:2.3rem}h2{margin-top:0;color:#193953}
section,.hero{background:white;border:1px solid #d8e0e8;border-radius:12px;padding:24px;margin:24px 0}
.hero{background:#183b54;color:white}.score{font-size:3.5rem;font-weight:700}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px}
.card{padding:16px;background:#eef3f7;border-radius:8px}.bar{height:10px;background:#d3dde5;border-radius:5px;margin-top:10px}.fill{height:100%;background:#416c8a;border-radius:5px}
.table-wrap{overflow:auto}table{border-collapse:collapse;width:100%;font-size:.9rem}th,td{text-align:left;vertical-align:top;border-bottom:1px solid #d8e0e8;padding:10px;overflow-wrap:anywhere;min-width:90px}th{background:#edf2f6}p{overflow-wrap:anywhere}
@media print{body{background:white}main{padding:0}section{break-inside:auto}.hero{color:#203047;background:white}}'''


def render_html(a,comparison):
    parts=['<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">',
           '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; img-src \'none\'">',
           '<title>Cybersecurity Quality Assessment Report</title><style>'+CSS+'</style></head><body><main>',
           '<h1>Cybersecurity Quality Assessment Report</h1>',
           '<div class="hero"><div>Cybersecurity Quality Index</div><div class="score">'+escape(number(a['cqi']['cqi']))+
           '<small> / 100</small></div><p>Quality index, not probability. No successful exploitation is confirmed.</p></div>',
           '<div class="cards">']
    for d in a['dimensions']:
        width=d['quality'] if d['quality'] is not None else 0
        parts.append('<div class="card"><strong>'+escape(d['dimension']+' '+d['name'])+'</strong><p>'+escape(number(d['quality']))+
                     ' / 100 &middot; '+escape(d['score_status'])+'</p><div class="bar"><div class="fill" style="width:'+str(width)+'%"></div></div></div>')
    parts.append('</div>')
    for section in sections(a,comparison):
        parts.append('<section><h2>'+escape(section['title'])+'</h2>')
        parts.extend('<p>'+escape(p)+'</p>' for p in section['paragraphs'])
        if section['headers']:
            parts.append('<div class="table-wrap"><table><thead><tr>'+''.join('<th>'+escape(x)+'</th>' for x in section['headers'])+'</tr></thead><tbody>')
            for row in section['rows']:parts.append('<tr>'+''.join('<td>'+escape(str(x))+'</td>' for x in row)+'</tr>')
            parts.append('</tbody></table></div>')
        parts.append('</section>')
    parts.append('</main></body></html>\n')
    return '\n'.join(parts)
