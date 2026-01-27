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
    map = L.map('map').setView([20, 0], 2);

    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        attribution: '© OpenStreetMap, © CartoDB',
        maxZoom: 19
    }).addTo(map);

    console.log('🗺️ Map initialized');
}

function updateMapMarkers(geoData) {
    // Supprimer les anciens marqueurs (simplified - en production utiliser une layer group)
    map.eachLayer((layer) => {
        if (layer instanceof L.Marker) {
            map.removeLayer(layer);
        }
    });

    // Ajouter les nouveaux marqueurs
    geoData.forEach(item => {
        if (item.latitude && item.longitude) {
            const marker = L.circleMarker([item.latitude, item.longitude], {
                radius: Math.min(item.count * 2, 20),
                fillColor: '#ef4444',
                color: '#fff',
                weight: 1,
                opacity: 0.8,
                fillOpacity: 0.6
            }).addTo(map);

            marker.bindPopup(`
                <strong>${item.country}</strong><br>
                ${item.city}<br>
                <em>${item.count} attacks</em>
            `);
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
                    color: '#f3f4f6'
                }
            }
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
                    '#ef4444',
                    '#f59e0b',
                    '#6366f1',
                    '#10b981'
                ],
                borderColor: '#1a1f3a',
                borderWidth: 2
            }]
        },
        options: {
            ...commonOptions,
            plugins: {
                ...commonOptions.plugins,
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#f3f4f6',
                        padding: 15,
                        font: {
                            size: 12
                        }
                    }
                }
            }
        }
    });

    // Timeline Chart (Line)
    const timelineCtx = document.getElementById('timelineChart').getContext('2d');
    timelineChart = new Chart(timelineCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Attacks',
                data: [],
                borderColor: '#6366f1',
                backgroundColor: 'rgba(99, 102, 241, 0.1)',
                tension: 0.4,
                fill: true
            }]
        },
        options: {
            ...commonOptions,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        color: '#9ca3af',
                        precision: 0
                    },
                    grid: {
                        color: '#2d3748'
                    }
                },
                x: {
                    ticks: {
                        color: '#9ca3af'
                    },
                    grid: {
                        color: '#2d3748'
                    }
                }
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
    typeChart.update('none'); // Pas d'animation pour updates fréquentes
}

function updateTimelineChart(timeline) {
    // Grouper par heure
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
                <td colspan="6" style="text-align: center; padding: 2rem; color: #6b7280;">
                    No alerts found
                </td>
            </tr>
        `;
        return;
    }

    const filtered = currentFilter === 'all'
        ? alerts
        : alerts.filter(a => a.attack_type === currentFilter);

    tbody.innerHTML = filtered.map(alert => `
        <tr>
            <td>${formatTimestamp(alert.timestamp)}</td>
            <td><span class="severity-badge severity-${alert.severity}">${alert.severity}</span></td>
            <td><span class="type-badge">${alert.attack_type}</span></td>
            <td>${alert.source_ip || 'unknown'}</td>
            <td>${alert.country || '-'}</td>
            <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                ${alert.pattern || '-'}
            </td>
        </tr>
    `).join('');
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

    document.getElementById('statSQLI').textContent = byType['SQL Injection'] || 0;
    document.getElementById('statXSS').textContent = byType['XSS'] || 0;
    document.getElementById('statBruteForce').textContent = byType['Brute Force'] || 0;
    document.getElementById('statTotal').textContent = stats.total || 0;
    document.getElementById('headerTotal').textContent = stats.total || 0;
}

// ==================== WEBSOCKET ====================
function initWebSocket() {
    ws = new WebSocket(WS_URL);

    ws.onopen = () => {
        console.log('✅ WebSocket connecté');
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
        setTimeout(initWebSocket, 5000);
    };
}

function handleNewAlert(alert) {
    // Ajouter en début de liste
    alertsData.unshift(alert);

    // Limiter à 100 alertes en mémoire
    if (alertsData.length > 100) {
        alertsData = alertsData.slice(0, 100);
    }

    // Re-render table
    renderAlertsTable(alertsData);

    // Animation flash
    const tbody = document.getElementById('alertsTableBody');
    const firstRow = tbody.querySelector('tr');
    if (firstRow) {
        firstRow.style.background = 'rgba(99, 102, 241, 0.3)';
        setTimeout(() => {
            firstRow.style.background = '';
        }, 1000);
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
            // Update active state
            filterBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            // Update filter
            currentFilter = btn.dataset.filter;

            // Re-render table
            renderAlertsTable(alertsData);
        });
    });
}

// ==================== DATA LOADING ====================
async function loadInitialData() {
    try {
        // Load stats
        const statsRes = await fetch(`${API_BASE}/api/stats`);
        const stats = await statsRes.json();

        updateStatsCards(stats);
        updateTypeChart(stats.by_type || {});
        updateTimelineChart(stats.timeline || []);
        updateMapMarkers(stats.geo_data || []);

        // Load alerts
        const alertsRes = await fetch(`${API_BASE}/api/alerts?limit=50`);
        const alertsData_json = await alertsRes.json();
        alertsData = alertsData_json.alerts || [];

        renderAlertsTable(alertsData);

        console.log('✅ Données initiales chargées');

    } catch (error) {
        console.error('❌ Erreur chargement:', error);
    }
}

// ==================== AUTO REFRESH ====================
setInterval(() => {
    // Rafraîchir les données toutes les 30 secondes (en backup du WebSocket)
    loadInitialData();
}, 30000);
