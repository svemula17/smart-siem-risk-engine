import re

with open('app/templates/dashboard.html') as f:
    html = f.read()

# Add CSS for new layout just before </style>
soar_css = """
        /* SOAR Layout Classes */
        .soar-container {
            display: flex;
            height: calc(100vh - 78px);
            width: 100vw;
            overflow: hidden;
            background: var(--bg-color);
        }
        .primary-sidebar {
            width: 70px;
            background: var(--bg-secondary);
            border-right: 1px solid var(--border-color);
            display: flex;
            flex-direction: column;
            align-items: center;
            padding-top: 1rem;
            gap: 1.5rem;
            z-index: 10;
        }
        .primary-sidebar-icon {
            width: 50px;
            height: 50px;
            display: flex;
            align-items: center;
            justify-content: center;
            flex-direction: column;
            color: var(--text-muted);
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.2s ease;
            font-size: 0.6rem;
            gap: 4px;
        }
        .primary-sidebar-icon:hover {
            color: var(--text-primary);
            background: rgba(255,255,255,0.05);
        }
        .primary-sidebar-icon.active {
            color: var(--accent-primary);
            background: rgba(59, 130, 246, 0.1);
            border-left: 3px solid var(--accent-primary);
            border-radius: 0 8px 8px 0;
        }
        .secondary-sidebar {
            width: 260px;
            background: var(--bg-color);
            border-right: 1px solid var(--border-color);
            padding: 1.5rem;
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
            overflow-y: auto;
        }
        .sub-menu-title {
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
            font-weight: 700;
            margin-bottom: 0.5rem;
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .sub-menu-item {
            padding: 8px 12px;
            color: var(--text-secondary);
            font-size: 0.85rem;
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.2s;
            margin-bottom: 2px;
        }
        .sub-menu-item:hover {
            background: rgba(255,255,255,0.03);
            color: var(--text-primary);
        }
        .sub-menu-item.active {
            background: rgba(255,255,255,0.05);
            color: var(--accent-primary);
            font-weight: 600;
            border-left: 2px solid var(--accent-primary);
            border-radius: 0 6px 6px 0;
        }
        .soar-main-content {
            flex-grow: 1;
            display: flex;
            flex-direction: column;
            padding: 1.5rem 2rem;
            gap: 1.5rem;
            overflow-y: auto;
            background: var(--bg-tertiary);
        }
        /* Top nav links */
        .top-nav-links {
            display: flex;
            gap: 1.5rem;
            margin-left: 2rem;
            font-size: 0.9rem;
            color: var(--text-secondary);
        }
        .top-nav-link {
            cursor: pointer;
            padding: 0.5rem;
            height: 100%;
        }
        .top-nav-link:hover { color: var(--text-primary); }
        .top-nav-link.active { color: var(--text-primary); border-bottom: 2px solid var(--accent-primary); font-weight: 600; padding-bottom: 4px; }

        .navbar { border-bottom: none; background: var(--bg-secondary); }
"""
html = html.replace('</style>', soar_css + '\n    </style>')

# Replace Top Nav Bar to include horizontal links
old_nav_end = '        </a>'
new_nav_addition = '''        </a>
        <div class="top-nav-links" style="flex-grow: 1; margin-left: 3rem; margin-top: 6px;">
            <div class="top-nav-link">Home</div>
            <div class="top-nav-link">Configurations</div>
            <div class="top-nav-link active">Attacks & Patches</div>
            <div class="top-nav-link">Software Deployment</div>
            <div class="top-nav-link">Inventory</div>
        </div>'''
html = html.replace(old_nav_end, new_nav_addition, 1)

# Modify Dashboard Wrapper
old_wrapper_start = '<div class="dashboard-wrapper">'
new_wrapper_start = '''<div class="soar-container">
    <aside class="primary-sidebar">
        <div class="primary-sidebar-icon">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18M9 21V9"/></svg>
            Dash
        </div>
        <div class="primary-sidebar-icon active">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            Attacks
        </div>
        <div class="primary-sidebar-icon">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            Patches
        </div>
        <div class="primary-sidebar-icon">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
            Systems
        </div>
        <div class="primary-sidebar-icon">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
            Reports
        </div>
        <div class="primary-sidebar-icon" style="margin-top: auto; margin-bottom: 1rem;">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>
            Settings
        </div>
    </aside>

    <aside class="secondary-sidebar">
        <div class="sub-menu-title" style="margin-bottom: 12px; color: var(--text-primary); font-size: 0.85rem;">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="transform: rotate(90deg);"><polyline points="8 15 12 19 16 15"></polyline><line x1="12" y1="5" x2="12" y2="19"></line></svg>
            Attacks
        </div>
        <div class="sub-menu-item active">Automated Remediations</div>
        <div class="sub-menu-item">Active Threats</div>
        <div class="sub-menu-item">System Misconfigurations</div>
        <div class="sub-menu-item">Zero-day Vulnerabilities</div>
        <div class="sub-menu-item">Manage Exceptions</div>

        <div style="height: 2rem;"></div>

        <div class="sub-menu-title">SIEM Core Stats</div>
        <div style="font-size: 0.8rem; color: var(--text-secondary); margin-bottom: 6px; padding: 0 12px; display: flex; justify-content: space-between;">Processed: <span style="font-family: monospace; font-weight:700">{{ raw_alert_count }}</span></div>
        <div style="font-size: 0.8rem; color: var(--text-secondary); margin-bottom: 6px; padding: 0 12px; display: flex; justify-content: space-between;">Scored Entities: <span style="font-family: monospace; font-weight:700">{{ scored_alert_count }}</span></div>
        <div style="font-size: 0.8rem; color: var(--text-secondary); margin-bottom: 6px; padding: 0 12px; display: flex; justify-content: space-between;">Auto-Blocks: <span style="font-family: monospace; font-weight:700; color: #ef4444;">{{ blocked_ip_count }}</span></div>

        <div style="height: 2rem;"></div>
        <div class="sub-menu-title" style="color: var(--status-critical);">Red-Team Simulator</div>
        <div style="padding: 0 12px;">
            <button class="btn-action" style="width: 100%; text-align: left; margin-bottom: 6px;" onclick="fetch('/proxy-test?query=union%20select%20admin').then(r => alert('Target Hit!\\nStatus: ' + r.status))">💉 Inject SQLi Payload</button>
            <button class="btn-action" style="width: 100%; text-align: left; margin-bottom: 6px;" onclick="fetch('/proxy-test?query=%3Cscript%3E').then(r => alert('Target Hit!\\nStatus: ' + r.status))">🐛 Inject XSS Payload</button>
            <button class="btn-action" style="width: 100%; text-align: left;" onclick="fetch('/proxy-test', {headers:{'User-Agent':'nmap'}}).then(r => alert('Target Hit!\\nStatus: ' + r.status))">🔍 Simulate Scan</button>
        </div>
    </aside>

    <div class="soar-main-content">
        <div style="display: flex; justify-content: space-between; align-items: flex-end;">
            <div>
                <h2 style="margin: 0 0 8px 0; font-size: 1.4rem; font-weight: 600;">Autonomous Remediation Feed</h2>
                <div style="font-size: 0.85rem; color: var(--text-secondary);">This table enumerates the attacks detected and inherently resolved by the Smart SIEM Risk engine. <a href="#" style="color: var(--accent-primary);">View the list of all remedies.</a></div>
            </div>
            <div style="display: flex; gap: 8px;">
                <button class="btn-action" style="background: rgba(34, 197, 94, 0.1); border-color: rgba(34,197,94,0.3); color: #22c55e; font-size: 0.8rem; padding: 8px 12px;">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align: middle; margin-right: 4px;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg> Policy Active
                </button>
                <button class="btn-action" style="font-size: 0.8rem; padding: 8px 12px;">Add Exceptions</button>
            </div>
        </div>
'''

html = html.replace(old_wrapper_start, new_wrapper_start)

# Strip out the old `<aside class="metrics-sidebar">` up to `</aside>`
html = re.sub(r'<aside class="metrics-sidebar">.*?</aside>', '', html, flags=re.DOTALL)

# Strip `.top-row` wrapper start
html = html.replace('<div class="top-row">', '')

# Adjust table headers
old_thead = '''                            <tr>
                                <th>Eval ID</th>
                                <th>Source Alert</th>
                                <th>Risk Score</th>
                                <th>Prescribed Action</th>
                                <th>Status</th>
                            </tr>'''
new_thead = '''                            <tr>
                                <th>Attack ID</th>
                                <th>Target / Source</th>
                                <th>Exploit Status</th>
                                <th>Remediation Action</th>
                                <th>Risk Score</th>
                            </tr>'''
html = html.replace(old_thead, new_thead)

# Adjust table body data rows to match. Since it's Jinja variables inside, I'll use regex to target the HTML tags inside the tr inside the loop
# Let's target the exact tr row block
old_tr_content_regex = r'<td class="mono id-cell" title="{{ alert\.id }}">.*?</td>\s*<td class="mono id-cell" title="{{ alert\.raw_alert_id }}">.*?</td>\s*<td class="mono score-renderer"[^>]*>.*?/100</td>\s*<td>\s*<span class="badge badge-action"[^>]*>.*?</span>\s*</td>\s*<td style="[^"]*">\s*{{ alert\.action_taken \| replace\(\'_\', \' \'\| title \)}}\s*</td>'
# Actually, the best way without risking regex mismatch on the huge block is to just completely wipe everything between `{% for alert in recent_scored_alerts %}` and `{% endfor %}` and rewrite it.
tbody_start = '{% for alert in recent_scored_alerts %}'
tbody_end = '{% endfor %}'

if tbody_start in html and tbody_end in html:
    sub_start = html.find(tbody_start) + len(tbody_start)
    sub_end = html.find(tbody_end, sub_start)
    new_tr = '''
                            <tr class="alert-row">
                                <td class="mono id-cell" title="{{ alert.id }}" style="color: var(--accent-primary);">ATK-{{ alert.id[:6] }}...</td>
                                <td class="mono" style="color: var(--text-primary); font-size: 0.8rem;">Network Perimeter</td>
                                <td style="color: #22c55e; font-weight: 600;"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:2px"><polyline points="20 6 9 17 4 12"></polyline></svg> Intercepted</td>
                                <td>
                                    <span class="badge badge-action badge-block">
                                        {{ alert.action_taken | replace('_', ' ') | upper }}
                                    </span>
                                </td>
                                <td class="mono score-renderer" data-score="{{ alert.risk_score }}">{{ alert.risk_score }}/100</td>
                            </tr>
                            '''
    html = html[:sub_start] + new_tr + html[sub_end:]

# Thread Feed panel visual updates
# Remove old title
old_feed_header = '''                <div class="panel-header">
                    <h2 class="panel-title">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right: 8px;">
                            <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline>
                        </svg>
                        Continuous Threat Feed
                    </h2>'''
new_feed_header = '''                <div class="panel-header" style="border-bottom: 1px solid var(--border-color); padding: 12px 1.5rem;">
                    <div style="display:flex; justify-content:flex-start; width:100%; align-items: center;">
                        <input type="radio" checked style="margin-right: 6px;"><label style="font-weight: 500; font-size: 0.85rem; color: var(--accent-primary); margin-right: 1.5rem;">Summary View</label>
                        <input type="radio" disabled style="margin-right: 6px;"><label style="font-weight: 500; font-size: 0.85rem; color: var(--text-muted);">Detailed View</label>
                    </div>'''
html = html.replace(old_feed_header, new_feed_header)

# Make table have a nice white/solid header if in light mode, or matching grey
html = html.replace('background: var(--table-header-bg);', 'background: var(--bg-secondary); border-top: 1px solid var(--border-color); border-bottom: 2px solid var(--border-color); color: var(--text-primary); text-transform: none; font-size: 0.8rem;')

with open('app/templates/dashboard.html', 'w') as f:
    f.write(html)
