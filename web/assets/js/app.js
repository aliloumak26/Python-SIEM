// SIEM Dashboard App
// Gestion des graphiques, WebSocket et mises à jour temps réel

// ==================== CONFIGURATION ====================
const API_BASE = window.location.origin;
const WS_URL = `ws://${window.location.host}/ws`;

// ==================== STATE ====================
let map = null;
let typeChart = null;
let timelineChart = null;
let ws = null;
let currentFilter = 'all';
let alertsData = [];

// ==================== INITIALIZATION ====================
document.addEventListener('DOMContentLoaded', () => {
    initMap();
    initCharts();
    initWebSocket();
    loadInitialData();
    setupFilters();

    console.log('🛡️ SIEM Dashboard initialized');
});

// ==================== MAP ====================
function initMap() {
    map = L.map('map', {
        zoomControl: true,
        scrollWheelZoom: true
    }).setView([30, 0], 2);

    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        attribution: '© OpenStreetMap, © CartoDB',
        maxZoom: 19
    }).addTo(map);

    console.log('🗺️ Map initialized');
}

function updateMapMarkers(geoData) {
    // Supprimer les anciens marqueurs
    map.eachLayer((layer) => {
        if (layer instanceof L.CircleMarker) {
            map.removeLayer(layer);
        }
    });

    // Ajouter les nouveaux marqueurs avec animation
    geoData.forEach((item, index) => {
        if (item.latitude && item.longitude) {
            setTimeout(() => {
                const marker = L.circleMarker([item.latitude, item.longitude], {
                    radius: Math.min(item.count * 2 + 4, 20),
                    fillColor: '#f87171',
                    color: 'rgba(248, 113, 113, 0.5)',
                    weight: 2,
                    opacity: 0.9,
                    fillOpacity: 0.6
                }).addTo(map);

                marker.bindPopup(`
                    <div style="font-family: Inter, sans-serif; padding: 4px;">
                        <strong style="color: #f87171;">${item.country || 'Unknown'}</strong><br>
                        <span style="color: #94a3b8;">${item.city || ''}</span><br>
                        <em style="color: #818cf8;">${item.count} attaque(s)</em>
                    </div>
                `);
            }, index * 50);
        }
    });
}

// ==================== CHARTS ====================
function initCharts() {
    const commonOptions = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                labels: {
                    color: '#94a3b8',
                    font: {
                        family: 'Inter',
                        size: 12
                    },
                    padding: 16
                }
            }
        },
        animation: {
            duration: 750,
            easing: 'easeOutQuart'
        }
    };

    // Type Chart (Doughnut)
    const typeCtx = document.getElementById('typeChart').getContext('2d');
    typeChart = new Chart(typeCtx, {
        type: 'doughnut',
        data: {
            labels: ['SQL Injection', 'XSS', 'Brute Force', 'ML Anomaly'],
            datasets: [{
                data: [0, 0, 0, 0],
                backgroundColor: [
                    'rgba(248, 113, 113, 0.8)',
                    'rgba(251, 191, 36, 0.8)',
                    'rgba(129, 140, 248, 0.8)',
                    'rgba(52, 211, 153, 0.8)'
                ],
                borderColor: 'rgba(15, 22, 41, 0.8)',
                borderWidth: 3,
                hoverOffset: 8
            }]
        },
        options: {
            ...commonOptions,
            cutout: '65%',
            plugins: {
                ...commonOptions.plugins,
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#94a3b8',
                        padding: 20,
                        font: {
                            family: 'Inter',
                            size: 12
                        },
                        usePointStyle: true,
                        pointStyle: 'circle'
                    }
                }
            }
        }
    });

    // Timeline Chart (Line)
    const timelineCtx = document.getElementById('timelineChart').getContext('2d');
    
    const gradient = timelineCtx.createLinearGradient(0, 0, 0, 280);
    gradient.addColorStop(0, 'rgba(129, 140, 248, 0.3)');
    gradient.addColorStop(1, 'rgba(129, 140, 248, 0)');

    timelineChart = new Chart(timelineCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Attaques',
                data: [],
                borderColor: '#818cf8',
                backgroundColor: gradient,
                tension: 0.4,
                fill: true,
                borderWidth: 2,
                pointBackgroundColor: '#818cf8',
                pointBorderColor: '#0f1629',
                pointBorderWidth: 2,
                pointRadius: 4,
                pointHoverRadius: 6
            }]
        },
        options: {
            ...commonOptions,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        color: '#64748b',
                        precision: 0,
                        font: {
                            family: 'Inter'
                        }
                    },
                    grid: {
                        color: 'rgba(148, 163, 184, 0.08)',
                        drawBorder: false
                    }
                },
                x: {
                    ticks: {
                        color: '#64748b',
                        font: {
                            family: 'Inter'
                        },
                        maxRotation: 0
                    },
                    grid: {
                        display: false
                    }
                }
            },
            interaction: {
                intersect: false,
                mode: 'index'
            }
        }
    });

    console.log('📊 Charts initialized');
}

function updateTypeChart(data) {
    const values = [
        data['SQL Injection'] || 0,
        data['XSS'] || 0,
        data['Brute Force'] || 0,
        data['ML Anomaly'] || 0
    ];

    typeChart.data.datasets[0].data = values;
    typeChart.update('none');
}

function updateTimelineChart(timeline) {
    const hourlyData = {};

    timeline.forEach(item => {
        const hour = item.hour;
        if (!hourlyData[hour]) {
            hourlyData[hour] = 0;
        }
        hourlyData[hour] += item.count;
    });

    const labels = Object.keys(hourlyData).map(h => {
        const date = new Date(h);
        return date.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' });
    });

    const data = Object.values(hourlyData);

    timelineChart.data.labels = labels;
    timelineChart.data.datasets[0].data = data;
    timelineChart.update('none');
}

// ==================== ALERTS TABLE ====================
function renderAlertsTable(alerts) {
    const tbody = document.getElementById('alertsTableBody');

    if (!alerts || alerts.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="6" style="text-align: center; padding: 3rem; color: #64748b;">
                    Aucune alerte trouvée
                </td>
            </tr>
        `;
        return;
    }

    const filtered = currentFilter === 'all'
        ? alerts
        : alerts.filter(a => a.attack_type === currentFilter);

    if (filtered.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="6" style="text-align: center; padding: 3rem; color: #64748b;">
                    Aucune alerte pour ce filtre
                </td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = filtered.map(alert => `
        <tr>
            <td style="white-space: nowrap;">${formatTimestamp(alert.timestamp)}</td>
            <td><span class="severity-badge severity-${alert.severity}">${alert.severity}</span></td>
            <td><span class="type-badge">${alert.attack_type}</span></td>
            <td style="font-family: monospace; font-size: 0.8125rem;">${alert.source_ip || 'N/A'}</td>
            <td>${alert.country || '—'}</td>
            <td style="max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(alert.pattern || '')}">
                ${alert.pattern || '—'}
            </td>
        </tr>
    `).join('');
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatTimestamp(ts) {
    const date = new Date(ts);
    return date.toLocaleString('fr-FR', {
        day: '2-digit',
        month: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
}

// ==================== STATS CARDS ====================
function updateStatsCards(stats) {
    const byType = stats.by_type || {};

    animateValue('statSQLI', byType['SQL Injection'] || 0);
    animateValue('statXSS', byType['XSS'] || 0);
    animateValue('statBruteForce', byType['Brute Force'] || 0);
    animateValue('statTotal', stats.total || 0);
    document.getElementById('headerTotal').textContent = stats.total || 0;
}

function animateValue(elementId, newValue) {
    const element = document.getElementById(elementId);
    const currentValue = parseInt(element.textContent) || 0;
    
    if (currentValue === newValue) return;
    
    const duration = 500;
    const startTime = performance.now();
    
    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        
        // Easing function
        const easeOut = 1 - Math.pow(1 - progress, 3);
        const value = Math.round(currentValue + (newValue - currentValue) * easeOut);
        
        element.textContent = value;
        
        if (progress < 1) {
            requestAnimationFrame(update);
        }
    }
    
    requestAnimationFrame(update);
}

// ==================== WEBSOCKET ====================
function initWebSocket() {
    ws = new WebSocket(WS_URL);

    ws.onopen = () => {
        console.log('✅ WebSocket connecté');
        document.getElementById('headerLive').textContent = '● LIVE';
    };

    ws.onmessage = (event) => {
        const message = JSON.parse(event.data);

        if (message.type === 'new_alert') {
            handleNewAlert(message.data);
        } else if (message.type === 'stats_update') {
            handleStatsUpdate(message.data);
        }
    };

    ws.onerror = (error) => {
        console.error('❌ WebSocket error:', error);
    };

    ws.onclose = () => {
        console.log('🔌 WebSocket fermé, reconnexion dans 5s...');
        document.getElementById('headerLive').textContent = '○ OFFLINE';
        document.getElementById('headerLive').classList.remove('pulse');
        setTimeout(initWebSocket, 5000);
    };
}

function handleNewAlert(alert) {
    alertsData.unshift(alert);

    if (alertsData.length > 100) {
        alertsData = alertsData.slice(0, 100);
    }

    renderAlertsTable(alertsData);

    // Animation flash pour la nouvelle alerte
    const tbody = document.getElementById('alertsTableBody');
    const firstRow = tbody.querySelector('tr');
    if (firstRow) {
        firstRow.classList.add('alert-new');
        setTimeout(() => {
            firstRow.classList.remove('alert-new');
        }, 1500);
    }

    console.log('🚨 Nouvelle alerte:', alert.attack_type);
}

function handleStatsUpdate(stats) {
    updateStatsCards(stats);
    updateTypeChart(stats.by_type || {});
}

// ==================== FILTERS ====================
function setupFilters() {
    const filterBtns = document.querySelectorAll('.filter-btn');

    filterBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            filterBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            currentFilter = btn.dataset.filter;
            renderAlertsTable(alertsData);
        });
    });
}

// ==================== DATA LOADING ====================
async function loadInitialData() {
    try {
        const statsRes = await fetch(`${API_BASE}/api/stats`);
        const stats = await statsRes.json();

        updateStatsCards(stats);
        updateTypeChart(stats.by_type || {});
        updateTimelineChart(stats.timeline || []);
        updateMapMarkers(stats.geo_data || []);

        const alertsRes = await fetch(`${API_BASE}/api/alerts?limit=50`);
        const alertsData_json = await alertsRes.json();
        alertsData = alertsData_json.alerts || [];

        renderAlertsTable(alertsData);

        console.log('✅ Données initiales chargées');

    } catch (error) {
        console.error('❌ Erreur chargement:', error);
        document.getElementById('alertsTableBody').innerHTML = `
            <tr>
                <td colspan="6" style="text-align: center; padding: 3rem; color: #f87171;">
                    Erreur de connexion au serveur
                </td>
            </tr>
        `;
    }
}

// ==================== AUTO REFRESH ====================
setInterval(() => {
    loadInitialData();
}, 30000);
