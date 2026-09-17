// PortZen High-Fidelity SOC Dashboard Controller
document.addEventListener('DOMContentLoaded', () => {
    const activityCanvas = document.getElementById('activityChart');
    const riskCanvas = document.getElementById('riskChart');

    let activityChart = null;
    let riskChart = null;

    // 1. Initialize Line Chart (Port Exposure Timeline)
    if (activityCanvas) {
        const ctx = activityCanvas.getContext('2d');
        const gradient = ctx.createLinearGradient(0, 0, 0, 260);
        gradient.addColorStop(0, 'rgba(37, 99, 235, 0.18)');
        gradient.addColorStop(1, 'rgba(37, 99, 235, 0.0)');

        const initTimeline = window.initialTimeline || {};
        const initLabels = initTimeline.labels || ['07:00', '07:10', '07:20', '07:30', '07:40', '07:50', '08:00'];
        const initData = initTimeline.values || [0, 0, 0, 0, 0, 0, 0];

        activityChart = new Chart(activityCanvas, {
            type: 'line',
            data: {
                labels: initLabels,
                datasets: [{
                    label: 'Open Ports',
                    data: initData,
                    borderColor: '#2563eb',
                    borderWidth: 2.5,
                    backgroundColor: gradient,
                    fill: true,
                    tension: 0.35,
                    pointRadius: 4,
                    pointHoverRadius: 6,
                    pointBackgroundColor: '#2563eb',
                    pointBorderColor: '#ffffff',
                    pointBorderWidth: 2,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: {
                    duration: 450,
                    easing: 'easeOutQuart'
                },
                interaction: {
                    mode: 'index',
                    intersect: false,
                },
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: '#0f172a',
                        titleColor: '#94a3b8',
                        titleFont: { size: 11, weight: '500' },
                        bodyColor: '#ffffff',
                        bodyFont: { size: 13, weight: '700' },
                        padding: { top: 8, bottom: 8, left: 12, right: 12 },
                        cornerRadius: 6,
                        displayColors: true,
                        boxWidth: 8,
                        boxHeight: 8,
                        usePointStyle: true,
                        callbacks: {
                            label: function(context) {
                                return ` Open Ports: ${context.parsed.y}`;
                            }
                        }
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Open Ports',
                            color: '#94a3b8',
                            font: { size: 11, weight: '500' }
                        },
                        grid: {
                            color: '#f1f5f9',
                            drawBorder: false,
                        },
                        ticks: {
                            precision: 0,
                            color: '#94a3b8',
                            font: { size: 11 }
                        }
                    },
                    x: {
                        grid: { display: false },
                        ticks: {
                            color: '#94a3b8',
                            font: { size: 11 }
                        }
                    }
                }
            }
        });
    }

    // 2. Initialize Donut Chart (Risk Distribution)
    if (riskCanvas) {
        riskChart = new Chart(riskCanvas, {
            type: 'doughnut',
            data: {
                labels: ['Low Risk', 'Medium Risk', 'High Risk'],
                datasets: [{
                    data: [65, 30, 5],
                    backgroundColor: ['#10b981', '#f59e0b', '#ef4444'],
                    borderWidth: 2,
                    borderColor: '#ffffff',
                    hoverOffset: 3
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '74%',
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: '#0f172a',
                        titleColor: '#ffffff',
                        bodyColor: '#e2e8f0',
                        cornerRadius: 6,
                        padding: 10,
                        callbacks: {
                            label: function(context) {
                                return ` ${context.label}: ${context.raw} (${context.parsed}%)`;
                            }
                        }
                    }
                }
            }
        });
    }

    // 3. Dropdown Controls (Time Range & Risk Scope)
    const activeTimeItem = document.querySelector('#timeRangeMenu .dropdown-item.active');
    let currentTimeRange = (activeTimeItem && activeTimeItem.dataset.range) ? activeTimeItem.dataset.range : '1h';

    const activeScopeItem = document.querySelector('#riskScopeMenu .dropdown-item.active');
    let currentRiskScope = (activeScopeItem && activeScopeItem.dataset.scope) ? activeScopeItem.dataset.scope : 'all';

    function closeDropdown(toggleBtn) {
        if (!toggleBtn) return;
        if (window.bootstrap && window.bootstrap.Dropdown) {
            try {
                const instance = window.bootstrap.Dropdown.getOrCreateInstance(toggleBtn);
                if (instance) {
                    instance.hide();
                }
            } catch (_) {}
        }
        const dropdown = toggleBtn.closest('.dropdown');
        if (dropdown) {
            const menu = dropdown.querySelector('.dropdown-menu');
            if (menu) menu.classList.remove('show');
            toggleBtn.classList.remove('show');
            toggleBtn.setAttribute('aria-expanded', 'false');
        }
    }

    // Time Range Dropdown Click Handlers
    const timeRangeBtn = document.getElementById('timeRangeDropdownBtn');
    const timeRangeLabel = document.getElementById('timeRangeLabel');
    const timeRangeItems = document.querySelectorAll('#timeRangeMenu .dropdown-item');

    timeRangeItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const range = item.dataset.range;
            if (!range) return;

            currentTimeRange = range;

            // Update active styling
            timeRangeItems.forEach(i => i.classList.remove('active'));
            item.classList.add('active');

            // Update button label
            if (timeRangeLabel) {
                timeRangeLabel.textContent = item.textContent.trim();
            }

            // Sync URL state so browser refresh preserves timeframe
            try {
                const url = new URL(window.location);
                url.searchParams.set('time_range', range);
                window.history.replaceState({}, '', url);
            } catch (_) {}

            closeDropdown(timeRangeBtn);
            refreshDashboard();
        });
    });

    // Risk Scope Dropdown Click Handlers
    const riskScopeBtn = document.getElementById('riskScopeDropdownBtn');
    const riskScopeLabel = document.getElementById('riskScopeLabel');
    const riskScopeItems = document.querySelectorAll('#riskScopeMenu .dropdown-item');

    riskScopeItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const scope = item.dataset.scope;
            if (!scope) return;

            currentRiskScope = scope;

            // Update active styling
            riskScopeItems.forEach(i => i.classList.remove('active'));
            item.classList.add('active');

            // Update button label
            if (riskScopeLabel) {
                riskScopeLabel.textContent = item.textContent.trim();
            }

            closeDropdown(riskScopeBtn);
            refreshDashboard();
        });
    });

    // Fallback toggle for environments where Bootstrap dropdown JS doesn't auto-bind
    function setupDropdownToggleFallback(btnId, menuId) {
        const btn = document.getElementById(btnId);
        const menu = document.getElementById(menuId);
        if (!btn || !menu) return;

        btn.addEventListener('click', (e) => {
            // Check if Bootstrap already managed it; if not, toggle manually
            setTimeout(() => {
                const hasBs = window.bootstrap && typeof window.bootstrap.Dropdown === 'function';
                if (!hasBs) {
                    const isOpen = menu.classList.contains('show');
                    if (isOpen) {
                        menu.classList.remove('show');
                        btn.classList.remove('show');
                        btn.setAttribute('aria-expanded', 'false');
                    } else {
                        menu.classList.add('show');
                        btn.classList.add('show');
                        btn.setAttribute('aria-expanded', 'true');
                    }
                }
            }, 10);
        });
    }

    setupDropdownToggleFallback('timeRangeDropdownBtn', 'timeRangeMenu');
    setupDropdownToggleFallback('riskScopeDropdownBtn', 'riskScopeMenu');

    // Close on click outside if opened via fallback
    document.addEventListener('click', (e) => {
        if (!e.target.closest('#timeRangeDropdownContainer')) {
            const menu = document.getElementById('timeRangeMenu');
            const btn = document.getElementById('timeRangeDropdownBtn');
            if (menu && menu.classList.contains('show') && (!window.bootstrap || !window.bootstrap.Dropdown)) {
                menu.classList.remove('show');
                if (btn) {
                    btn.classList.remove('show');
                    btn.setAttribute('aria-expanded', 'false');
                }
            }
        }
        if (!e.target.closest('#riskScopeDropdownContainer')) {
            const menu = document.getElementById('riskScopeMenu');
            const btn = document.getElementById('riskScopeDropdownBtn');
            if (menu && menu.classList.contains('show') && (!window.bootstrap || !window.bootstrap.Dropdown)) {
                menu.classList.remove('show');
                if (btn) {
                    btn.classList.remove('show');
                    btn.setAttribute('aria-expanded', 'false');
                }
            }
        }
    });

    // 4. Asynchronous Live Updates
    async function refreshDashboard() {
        const hostSelector = document.getElementById('hostSelector');
        const hostId = hostSelector ? hostSelector.value : '';

        try {
            const resp = await fetch(`/api/dashboard/stats?host_id=${encodeURIComponent(hostId)}&time_range=${encodeURIComponent(currentTimeRange)}&risk_scope=${encodeURIComponent(currentRiskScope)}`);
            if (!resp.ok) return;
            const data = await resp.json();

            // Metric Cards
            const elOpen = document.getElementById('metric-open-ports');
            const elNew = document.getElementById('metric-new-ports');
            const elClosed = document.getElementById('metric-closed-ports');
            const elHigh = document.getElementById('metric-high-risk');
            const elHighSub = document.getElementById('metric-high-risk-sub');
            const elAlerts = document.getElementById('metric-active-alerts');

            if (elOpen) elOpen.textContent = data.open_ports;
            if (elNew) elNew.textContent = data.new_ports;
            if (elClosed) elClosed.textContent = data.closed_ports;
            if (elHigh) {
                elHigh.textContent = data.high_risk;
                if (elHighSub) {
                    elHighSub.textContent = data.high_risk === 0 ? 'No high risk ports' : `${data.high_risk} critical exposure`;
                }
            }
            if (elAlerts) elAlerts.textContent = data.active_alerts;

            // Donut Center Total
            const elDonutTotal = document.getElementById('donut-total-val');
            if (elDonutTotal) {
                elDonutTotal.textContent = (data.risk_distribution && data.risk_distribution.TOTAL !== undefined) 
                    ? data.risk_distribution.TOTAL 
                    : data.open_ports;
            }

            // Risk Breakdown
            if (data.risk_distribution) {
                const dist = data.risk_distribution;
                const elLowPct = document.getElementById('dist-low-pct');
                const elLowCnt = document.getElementById('dist-low-cnt');
                const elMedPct = document.getElementById('dist-med-pct');
                const elMedCnt = document.getElementById('dist-med-cnt');
                const elHighPct = document.getElementById('dist-high-pct');
                const elHighCnt = document.getElementById('dist-high-cnt');

                if (elLowPct) elLowPct.textContent = `${dist.LOW_PCT}%`;
                if (elLowCnt) elLowCnt.textContent = dist.LOW;
                if (elMedPct) elMedPct.textContent = `${dist.MED_PCT}%`;
                if (elMedCnt) elMedCnt.textContent = dist.MEDIUM;
                if (elHighPct) elHighPct.textContent = `${dist.HIGH_PCT}%`;
                if (elHighCnt) elHighCnt.textContent = dist.HIGH;

                if (riskChart) {
                    riskChart.data.datasets[0].data = [dist.LOW, dist.MEDIUM, dist.HIGH];
                    riskChart.update();
                }
            }

            // Timeline Chart
            if (activityChart && data.timeline) {
                activityChart.data.labels = data.timeline.labels;
                activityChart.data.datasets[0].data = data.timeline.values;
                activityChart.update();

                const subtitle = document.getElementById('timelineSubtitle');
                if (subtitle) {
                    const rangeSubtitles = {
                        '1h': 'Total open ports over the last hour',
                        '6h': 'Total open ports over the last 6 hours',
                        '24h': 'Total open ports over the last 24 hours',
                        '7d': 'Total open ports over the last 7 days'
                    };
                    subtitle.textContent = rangeSubtitles[data.timeline.time_range] || 'Total open ports over time';
                }
            }

            // Status Timestamps
            const elLastScan = document.getElementById('stat-last-scan');
            const elLastScanSub = document.getElementById('stat-last-scan-sub');
            const elNextScan = document.getElementById('stat-next-scan');
            const elNextScanSub = document.getElementById('stat-next-scan-sub');
            const elStatusBadge = document.getElementById('dashboard-monitoring-badge');

            if (elLastScan) elLastScan.textContent = data.last_scan || 'Never';
            if (elLastScanSub) elLastScanSub.textContent = data.last_scan_sub || '';
            if (elNextScan) elNextScan.textContent = data.next_scan || '—';
            if (elNextScanSub) elNextScanSub.textContent = data.next_scan_sub || '';

            if (elStatusBadge) {
                if (data.is_monitoring) {
                    elStatusBadge.className = 'navbar-status-pill status-active';
                    elStatusBadge.innerHTML = '<span class="pulse-dot"></span><span class="status-pill-text">Monitoring Active</span>';
                } else {
                    elStatusBadge.className = 'navbar-status-pill status-stopped';
                    elStatusBadge.innerHTML = '<span class="pulse-dot"></span><span class="status-pill-text">Monitoring Stopped</span>';
                }
            }
        } catch (err) {
            console.warn('Dashboard auto-refresh error:', err);
        }
    }

    const hostSelector = document.getElementById('hostSelector');
    if (hostSelector) {
        hostSelector.addEventListener('change', () => {
            const newHostId = hostSelector.value;
            window.location.href = `/dashboard?host_id=${encodeURIComponent(newHostId)}&time_range=${encodeURIComponent(currentTimeRange)}&risk_scope=${encodeURIComponent(currentRiskScope)}`;
        });
    }

    // Refresh immediately and set 10s poll
    refreshDashboard();
    setInterval(refreshDashboard, 10000);
});
