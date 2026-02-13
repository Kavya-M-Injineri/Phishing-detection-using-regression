/**
 * Phishing Detection App — Frontend Logic
 * =========================================
 * Handles JWT authentication, API calls, Chart.js visualizations,
 * page navigation, form submissions, and UI effects.
 */

// ─── Configuration ───
const API_BASE = '';
const TOKEN_KEY = 'phishing_auth_token';
const USER_KEY  = 'phishing_user';

// ─── Feature definitions (48 features grouped by category) ───
const FEATURE_CATEGORIES = {
    'URL Structure': [
        { name: 'NumDots', label: 'Number of Dots', desc: 'Count of dots in URL' },
        { name: 'SubdomainLevel', label: 'Subdomain Level', desc: 'Depth of subdomains' },
        { name: 'PathLevel', label: 'Path Level', desc: 'Depth of URL path' },
        { name: 'UrlLength', label: 'URL Length', desc: 'Total length of URL' },
        { name: 'NumDash', label: 'Number of Dashes', desc: 'Count of dashes in URL' },
        { name: 'NumDashInHostname', label: 'Dashes in Hostname', desc: 'Dashes in the hostname' },
        { name: 'NumUnderscore', label: 'Underscores', desc: 'Count of underscores' },
        { name: 'NumPercent', label: 'Percent Symbols', desc: 'Count of % symbols' },
        { name: 'NumQueryComponents', label: 'Query Components', desc: 'Number of query parameters' },
        { name: 'NumAmpersand', label: 'Ampersands', desc: 'Count of & symbols' },
        { name: 'NumHash', label: 'Hash Symbols', desc: 'Count of # symbols' },
        { name: 'NumNumericChars', label: 'Numeric Characters', desc: 'Count of digits' },
        { name: 'HostnameLength', label: 'Hostname Length', desc: 'Length of hostname' },
        { name: 'PathLength', label: 'Path Length', desc: 'Length of URL path' },
        { name: 'QueryLength', label: 'Query Length', desc: 'Length of query string' },
        { name: 'DoubleSlashInPath', label: 'Double Slash in Path', desc: 'Contains // in path' },
    ],
    'Suspicious Symbols': [
        { name: 'AtSymbol', label: '@ Symbol', desc: 'Contains @ in URL' },
        { name: 'TildeSymbol', label: '~ Symbol', desc: 'Contains tilde' },
        { name: 'NoHttps', label: 'No HTTPS', desc: 'Missing HTTPS' },
        { name: 'RandomString', label: 'Random String', desc: 'Contains random chars' },
        { name: 'IpAddress', label: 'IP Address', desc: 'Uses IP instead of domain' },
    ],
    'Domain Analysis': [
        { name: 'DomainInSubdomains', label: 'Domain in Subdomains', desc: 'Domain name in subdomain' },
        { name: 'DomainInPaths', label: 'Domain in Paths', desc: 'Domain name in path' },
        { name: 'HttpsInHostname', label: 'HTTPS in Hostname', desc: 'HTTPS word in hostname' },
        { name: 'NumSensitiveWords', label: 'Sensitive Words', desc: 'Count of sensitive keywords' },
        { name: 'EmbeddedBrandName', label: 'Embedded Brand Name', desc: 'Known brand in URL' },
        { name: 'FrequentDomainNameMismatch', label: 'Domain Mismatch', desc: 'Domain name inconsistency' },
    ],
    'Page Content': [
        { name: 'PctExtHyperlinks', label: '% External Hyperlinks', desc: 'External link ratio' },
        { name: 'PctExtResourceUrls', label: '% External Resources', desc: 'External resource ratio' },
        { name: 'ExtFavicon', label: 'External Favicon', desc: 'Favicon from external domain' },
        { name: 'InsecureForms', label: 'Insecure Forms', desc: 'Forms without HTTPS' },
        { name: 'RelativeFormAction', label: 'Relative Form Action', desc: 'Form with relative action' },
        { name: 'ExtFormAction', label: 'External Form Action', desc: 'Form sends to external URL' },
        { name: 'AbnormalFormAction', label: 'Abnormal Form Action', desc: 'Unusual form action' },
        { name: 'PctNullSelfRedirectHyperlinks', label: '% Null/Self Redirect Links', desc: 'Self-referencing links' },
        { name: 'FakeLinkInStatusBar', label: 'Fake Status Bar Link', desc: 'Status bar manipulation' },
        { name: 'RightClickDisabled', label: 'Right Click Disabled', desc: 'Context menu blocked' },
        { name: 'PopUpWindow', label: 'Pop-Up Window', desc: 'Uses pop-up windows' },
        { name: 'SubmitInfoToEmail', label: 'Submit to Email', desc: 'Form sends via email' },
        { name: 'IframeOrFrame', label: 'IFrame/Frame', desc: 'Uses frames' },
        { name: 'MissingTitle', label: 'Missing Title', desc: 'No page title' },
        { name: 'ImagesOnlyInForm', label: 'Images Only in Form', desc: 'Form has only images' },
    ],
    'Real-Time Features': [
        { name: 'SubdomainLevelRT', label: 'Subdomain Level (RT)', desc: 'Real-time subdomain check' },
        { name: 'UrlLengthRT', label: 'URL Length (RT)', desc: 'Real-time URL length check' },
        { name: 'PctExtResourceUrlsRT', label: '% External Resources (RT)', desc: 'Real-time external resources' },
        { name: 'AbnormalExtFormActionR', label: 'Abnormal Form Action (RT)', desc: 'Real-time form check' },
        { name: 'ExtMetaScriptLinkRT', label: 'External Meta/Script (RT)', desc: 'Real-time script check' },
        { name: 'PctExtNullSelfRedirectHyperlinksRT', label: '% Null Redirect (RT)', desc: 'Real-time redirect check' },
    ],
};


// ============================================================
// JWT Token Management
// ============================================================

function getToken() {
    return localStorage.getItem(TOKEN_KEY);
}

function setToken(token) {
    localStorage.setItem(TOKEN_KEY, token);
}

function getUser() {
    const data = localStorage.getItem(USER_KEY);
    return data ? JSON.parse(data) : null;
}

function setUser(user) {
    localStorage.setItem(USER_KEY, JSON.stringify(user));
}

function logout() {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
    window.location.href = '/login';
}

function isAuthenticated() {
    return !!getToken();
}

function authHeaders() {
    return {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${getToken()}`
    };
}


// ============================================================
// API Helper
// ============================================================

async function apiCall(url, options = {}) {
    try {
        const response = await fetch(API_BASE + url, {
            headers: authHeaders(),
            ...options,
        });

        const data = await response.json();

        if (response.status === 401) {
            showToast('Session expired. Please login again.', 'warning');
            setTimeout(() => logout(), 1500);
            return null;
        }

        if (!response.ok) {
            throw new Error(data.error || `Request failed (${response.status})`);
        }

        return data;
    } catch (error) {
        console.error('API Error:', error);
        throw error;
    }
}


// ============================================================
// Toast Notifications
// ============================================================

function showToast(message, type = 'info', duration = 4000) {
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        container.className = 'toast-container';
        document.body.appendChild(container);
    }

    const icons = {
        success: '✓',
        error: '✕',
        warning: '⚠',
        info: 'ℹ'
    };

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
        <span class="toast-icon">${icons[type]}</span>
        <span class="toast-message">${message}</span>
        <button class="toast-close" onclick="this.parentElement.remove()">×</button>
    `;

    container.appendChild(toast);

    setTimeout(() => {
        toast.style.animation = 'toastOut 0.3s ease forwards';
        setTimeout(() => toast.remove(), 300);
    }, duration);
}


// ============================================================
// Loading Spinner
// ============================================================

function showSpinner(text = 'Loading...') {
    let overlay = document.getElementById('spinner-overlay');
    if (!overlay) {
        overlay = document.createElement('div');
        overlay.id = 'spinner-overlay';
        overlay.className = 'spinner-overlay';
        overlay.innerHTML = `
            <div class="spinner"></div>
            <p class="spinner-text">${text}</p>
        `;
        document.body.appendChild(overlay);
    } else {
        overlay.querySelector('.spinner-text').textContent = text;
    }
    requestAnimationFrame(() => overlay.classList.add('active'));
}

function hideSpinner() {
    const overlay = document.getElementById('spinner-overlay');
    if (overlay) {
        overlay.classList.remove('active');
    }
}


// ============================================================
// Auth: Login
// ============================================================

async function handleLogin(event) {
    event.preventDefault();
    const form = event.target;
    const username = form.querySelector('#username').value.trim();
    const password = form.querySelector('#password').value;

    if (!username || !password) {
        showToast('Please fill in all fields', 'warning');
        return;
    }

    const submitBtn = form.querySelector('button[type="submit"]');
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<span class="spinner" style="width:20px;height:20px;border-width:2px;margin:0"></span> Signing in...';

    try {
        const response = await fetch(API_BASE + '/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Login failed');
        }

        setToken(data.token);
        setUser(data.user);
        showToast('Login successful! Redirecting...', 'success');
        setTimeout(() => window.location.href = '/dashboard', 800);
    } catch (error) {
        showToast(error.message, 'error');
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<i class="fas fa-sign-in-alt"></i> Sign In';
    }
}


// ============================================================
// Auth: Signup
// ============================================================

async function handleSignup(event) {
    event.preventDefault();
    const form = event.target;
    const username = form.querySelector('#username').value.trim();
    const email    = form.querySelector('#email').value.trim();
    const password = form.querySelector('#password').value;
    const confirm  = form.querySelector('#confirm-password').value;

    if (!username || !email || !password || !confirm) {
        showToast('Please fill in all fields', 'warning');
        return;
    }

    if (password !== confirm) {
        showToast('Passwords do not match', 'error');
        return;
    }

    if (password.length < 6) {
        showToast('Password must be at least 6 characters', 'warning');
        return;
    }

    const submitBtn = form.querySelector('button[type="submit"]');
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<span class="spinner" style="width:20px;height:20px;border-width:2px;margin:0"></span> Creating account...';

    try {
        const response = await fetch(API_BASE + '/api/signup', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, email, password })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Signup failed');
        }

        setToken(data.token);
        setUser(data.user);
        showToast('Account created! Redirecting...', 'success');
        setTimeout(() => window.location.href = '/dashboard', 800);
    } catch (error) {
        showToast(error.message, 'error');
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<i class="fas fa-user-plus"></i> Create Account';
    }
}


// ============================================================
// Dashboard
// ============================================================

async function loadDashboard() {
    if (!isAuthenticated()) {
        window.location.href = '/login';
        return;
    }

    const user = getUser();
    const welcomeEl = document.getElementById('welcome-username');
    if (welcomeEl && user) {
        welcomeEl.textContent = user.username;
    }

    // Load health/stats
    try {
        const health = await apiCall('/api/health');
        const modelStatus = document.getElementById('model-status');
        if (modelStatus) {
            modelStatus.textContent = health.model_ready ? 'Trained & Ready' : 'Not Trained';
            modelStatus.className = `stat-value ${health.model_ready ? '' : 'text-warning'}`;
        }
    } catch (e) {
        console.error('Failed to load health:', e);
    }

    // Load analytics summary if available
    try {
        const data = await apiCall('/api/analytics');
        if (data && data.analytics) {
            const a = data.analytics;
            updateElement('total-samples', a.dataset?.total_samples?.toLocaleString());
            updateElement('num-features', a.dataset?.num_features);
            updateElement('phishing-count', a.dataset?.phishing_count?.toLocaleString());
            updateElement('legit-count', a.dataset?.legitimate_count?.toLocaleString());

            if (a.training_history) {
                const acc = a.training_history.val_accuracy;
                updateElement('model-accuracy', (acc[acc.length - 1] * 100).toFixed(1) + '%');
                updateElement('epochs-trained', a.training_history.epochs_trained);
            }
        }
    } catch (e) {
        console.error('Failed to load analytics summary:', e);
    }
}


// ============================================================
// Prediction
// ============================================================

function buildPredictForm() {
    const container = document.getElementById('feature-form-fields');
    if (!container) return;

    let html = '';
    for (const [category, features] of Object.entries(FEATURE_CATEGORIES)) {
        html += `<div class="feature-category">
            <h3><i class="fas fa-layer-group"></i> ${category}</h3>
            <div class="predict-grid">`;

        for (const feat of features) {
            html += `
                <div class="form-group">
                    <label class="form-label" for="feat-${feat.name}" title="${feat.desc}">${feat.label}</label>
                    <input type="number" class="form-input" id="feat-${feat.name}"
                           name="${feat.name}" value="0" step="any"
                           placeholder="${feat.desc}">
                </div>`;
        }

        html += `</div></div>`;
    }

    container.innerHTML = html;
}

async function handlePredict(event) {
    event.preventDefault();

    if (!isAuthenticated()) {
        showToast('Please login first', 'warning');
        return;
    }

    // Collect all feature values
    const features = {};
    for (const [, feats] of Object.entries(FEATURE_CATEGORIES)) {
        for (const feat of feats) {
            const input = document.getElementById(`feat-${feat.name}`);
            features[feat.name] = parseFloat(input?.value || 0);
        }
    }

    showSpinner('Analyzing URL features...');

    try {
        const data = await apiCall('/api/predict', {
            method: 'POST',
            body: JSON.stringify({ features })
        });

        hideSpinner();

        if (data && data.prediction) {
            displayPredictionResult(data.prediction);
        }
    } catch (error) {
        hideSpinner();
        showToast(error.message, 'error');
    }
}

function displayPredictionResult(prediction) {
    // Store result for results page
    sessionStorage.setItem('prediction_result', JSON.stringify(prediction));

    // If results container is on same page, show inline
    const resultsSection = document.getElementById('prediction-results');
    if (resultsSection) {
        resultsSection.classList.remove('hidden');
        animateGauge(prediction);
        resultsSection.scrollIntoView({ behavior: 'smooth' });
    } else {
        window.location.href = '/results';
    }
}

function animateGauge(prediction) {
    const score = prediction.score;
    const percentage = prediction.percentage;

    // Update score text
    updateElement('result-score', percentage + '%');
    updateElement('result-status', prediction.status);

    // Set status badge
    const badge = document.getElementById('status-badge');
    if (badge) {
        badge.textContent = prediction.status;
        badge.className = `status-badge ${prediction.label}`;
    }

    // Animate the SVG gauge
    const gaugeFill = document.getElementById('gauge-fill');
    if (gaugeFill) {
        const circumference = 2 * Math.PI * 90; // r=90
        const offset = circumference - (score * circumference);

        // Color based on risk
        let color;
        if (prediction.label === 'danger') color = '#fda4af';
        else if (prediction.label === 'warning') color = '#fcd34d';
        else color = '#86efac';

        gaugeFill.style.stroke = color;
        setTimeout(() => {
            gaugeFill.style.strokeDashoffset = offset;
        }, 100);
    }

    // Update score number color
    const scoreNum = document.getElementById('score-number');
    if (scoreNum) {
        if (prediction.label === 'danger') scoreNum.style.color = '#fda4af';
        else if (prediction.label === 'warning') scoreNum.style.color = '#fcd34d';
        else scoreNum.style.color = '#86efac';
        scoreNum.textContent = percentage + '%';
    }
}


// ============================================================
// Batch Prediction
// ============================================================

async function handleBatchUpload(event) {
    event.preventDefault();

    if (!isAuthenticated()) {
        showToast('Please login first', 'warning');
        return;
    }

    const fileInput = document.getElementById('batch-file');
    if (!fileInput || !fileInput.files[0]) {
        showToast('Please select a CSV file', 'warning');
        return;
    }

    const formData = new FormData();
    formData.append('file', fileInput.files[0]);

    showSpinner('Processing batch predictions...');

    try {
        const response = await fetch(API_BASE + '/api/batch-predict', {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${getToken()}` },
            body: formData
        });

        const data = await response.json();
        hideSpinner();

        if (!response.ok) {
            throw new Error(data.error || 'Batch prediction failed');
        }

        displayBatchResults(data);
        showToast(`Processed ${data.count} samples!`, 'success');
    } catch (error) {
        hideSpinner();
        showToast(error.message, 'error');
    }
}

function displayBatchResults(data) {
    const container = document.getElementById('batch-results');
    if (!container) return;

    container.classList.remove('hidden');

    // Summary
    const summary = data.summary;
    document.getElementById('batch-summary').innerHTML = `
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-icon green"><i class="fas fa-check-circle"></i></div>
                <div class="stat-value">${summary.legitimate}</div>
                <div class="stat-label">Legitimate</div>
            </div>
            <div class="stat-card">
                <div class="stat-icon amber"><i class="fas fa-exclamation-triangle"></i></div>
                <div class="stat-value">${summary.suspicious}</div>
                <div class="stat-label">Suspicious</div>
            </div>
            <div class="stat-card">
                <div class="stat-icon pink"><i class="fas fa-skull-crossbones"></i></div>
                <div class="stat-value">${summary.phishing}</div>
                <div class="stat-label">Phishing</div>
            </div>
            <div class="stat-card">
                <div class="stat-icon purple"><i class="fas fa-chart-line"></i></div>
                <div class="stat-value">${(summary.avg_score * 100).toFixed(1)}%</div>
                <div class="stat-label">Avg Risk Score</div>
            </div>
        </div>
    `;

    // Table
    let tableHtml = `
        <table class="data-table">
            <thead><tr>
                <th>#</th><th>Score</th><th>Risk %</th><th>Status</th>
            </tr></thead><tbody>`;

    data.predictions.forEach((p, i) => {
        const statusClass = p.status === 'Phishing' ? 'danger' : (p.status === 'Suspicious' ? 'warning' : 'safe');
        tableHtml += `<tr>
            <td>${i + 1}</td>
            <td>${p.phishing_score}</td>
            <td>${p.phishing_percentage}%</td>
            <td><span class="status-badge ${statusClass}" style="padding:4px 12px;font-size:0.75rem">${p.status}</span></td>
        </tr>`;
    });

    tableHtml += '</tbody></table>';
    document.getElementById('batch-table').innerHTML = `<div class="batch-results">${tableHtml}</div>`;
}


// ============================================================
// Analytics Charts
// ============================================================

let chartInstances = {};

async function loadAnalytics() {
    if (!isAuthenticated()) {
        window.location.href = '/login';
        return;
    }

    showSpinner('Loading analytics...');

    try {
        const data = await apiCall('/api/analytics');
        hideSpinner();

        if (!data || !data.analytics) {
            showToast('No analytics data available. Train the model first.', 'warning');
            return;
        }

        const analytics = data.analytics;

        // Class distribution doughnut
        if (analytics.dataset) {
            renderClassDistribution(analytics.dataset);
        }

        // Feature importance bar chart
        if (analytics.feature_importance) {
            renderFeatureImportance(analytics.feature_importance);
        }

        // Training history line chart
        if (analytics.training_history) {
            renderTrainingHistory(analytics.training_history);
            renderAUCHistory(analytics.training_history);
        }

    } catch (error) {
        hideSpinner();
        showToast('Failed to load analytics: ' + error.message, 'error');
    }
}

function renderClassDistribution(dataset) {
    const ctx = document.getElementById('class-distribution-chart');
    if (!ctx) return;

    if (chartInstances.classDist) chartInstances.classDist.destroy();

    chartInstances.classDist = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Legitimate', 'Phishing'],
            datasets: [{
                data: [dataset.legitimate_count, dataset.phishing_count],
                backgroundColor: ['rgba(134, 239, 172, 0.8)', 'rgba(253, 164, 175, 0.8)'],
                borderColor: ['rgba(134, 239, 172, 1)', 'rgba(253, 164, 175, 1)'],
                borderWidth: 2,
                hoverOffset: 10,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#9d9db5', font: { family: 'Inter', size: 13 }, padding: 20 }
                },
                title: { display: false }
            },
            cutout: '65%',
        }
    });
}

function renderFeatureImportance(importance) {
    const ctx = document.getElementById('feature-importance-chart');
    if (!ctx) return;

    if (chartInstances.featImp) chartInstances.featImp.destroy();

    // Top 15 features
    const entries = Object.entries(importance).slice(0, 15);
    const labels = entries.map(e => e[0]);
    const values = entries.map(e => e[1]);

    chartInstances.featImp = new Chart(ctx, {
        type: 'bar',
        data: {
            labels,
            datasets: [{
                label: 'Importance (accuracy drop)',
                data: values,
                backgroundColor: values.map((_, i) => {
                    const colors = [
                        'rgba(167, 139, 250, 0.7)',
                        'rgba(103, 232, 249, 0.7)',
                        'rgba(240, 171, 252, 0.7)',
                        'rgba(134, 239, 172, 0.7)',
                        'rgba(252, 211, 77, 0.7)',
                    ];
                    return colors[i % colors.length];
                }),
                borderRadius: 6,
                borderSkipped: false,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            indexAxis: 'y',
            plugins: {
                legend: { display: false },
            },
            scales: {
                x: {
                    grid: { color: 'rgba(167, 139, 250, 0.06)' },
                    ticks: { color: '#9d9db5', font: { family: 'Inter' } }
                },
                y: {
                    grid: { display: false },
                    ticks: { color: '#e8e8f0', font: { family: 'Inter', size: 12 } }
                }
            }
        }
    });
}

function renderTrainingHistory(history) {
    const ctx = document.getElementById('training-history-chart');
    if (!ctx) return;

    if (chartInstances.trainHist) chartInstances.trainHist.destroy();

    const epochs = Array.from({ length: history.loss.length }, (_, i) => i + 1);

    chartInstances.trainHist = new Chart(ctx, {
        type: 'line',
        data: {
            labels: epochs,
            datasets: [
                {
                    label: 'Training Loss',
                    data: history.loss,
                    borderColor: 'rgba(167, 139, 250, 1)',
                    backgroundColor: 'rgba(167, 139, 250, 0.1)',
                    fill: true,
                    tension: 0.4,
                    pointRadius: 3,
                    pointHoverRadius: 6,
                },
                {
                    label: 'Validation Loss',
                    data: history.val_loss,
                    borderColor: 'rgba(103, 232, 249, 1)',
                    backgroundColor: 'rgba(103, 232, 249, 0.1)',
                    fill: true,
                    tension: 0.4,
                    pointRadius: 3,
                    pointHoverRadius: 6,
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { mode: 'index', intersect: false },
            plugins: {
                legend: {
                    labels: { color: '#9d9db5', font: { family: 'Inter' }, usePointStyle: true, padding: 20 }
                }
            },
            scales: {
                x: {
                    title: { display: true, text: 'Epoch', color: '#9d9db5' },
                    grid: { color: 'rgba(167, 139, 250, 0.06)' },
                    ticks: { color: '#9d9db5' }
                },
                y: {
                    title: { display: true, text: 'Loss', color: '#9d9db5' },
                    grid: { color: 'rgba(167, 139, 250, 0.06)' },
                    ticks: { color: '#9d9db5' }
                }
            }
        }
    });
}

function renderAUCHistory(history) {
    const ctx = document.getElementById('auc-history-chart');
    if (!ctx) return;

    if (chartInstances.aucHist) chartInstances.aucHist.destroy();

    const epochs = Array.from({ length: history.accuracy.length }, (_, i) => i + 1);

    chartInstances.aucHist = new Chart(ctx, {
        type: 'line',
        data: {
            labels: epochs,
            datasets: [
                {
                    label: 'Training Accuracy',
                    data: history.accuracy,
                    borderColor: 'rgba(134, 239, 172, 1)',
                    backgroundColor: 'rgba(134, 239, 172, 0.1)',
                    fill: true,
                    tension: 0.4,
                    pointRadius: 3,
                },
                {
                    label: 'Validation Accuracy',
                    data: history.val_accuracy,
                    borderColor: 'rgba(252, 211, 77, 1)',
                    backgroundColor: 'rgba(252, 211, 77, 0.1)',
                    fill: true,
                    tension: 0.4,
                    pointRadius: 3,
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { mode: 'index', intersect: false },
            plugins: {
                legend: {
                    labels: { color: '#9d9db5', font: { family: 'Inter' }, usePointStyle: true, padding: 20 }
                }
            },
            scales: {
                x: {
                    title: { display: true, text: 'Epoch', color: '#9d9db5' },
                    grid: { color: 'rgba(167, 139, 250, 0.06)' },
                    ticks: { color: '#9d9db5' }
                },
                y: {
                    title: { display: true, text: 'Accuracy', color: '#9d9db5' },
                    grid: { color: 'rgba(167, 139, 250, 0.06)' },
                    ticks: { color: '#9d9db5' },
                    min: 0, max: 1,
                }
            }
        }
    });
}


// ============================================================
// UI Helpers
// ============================================================

function updateElement(id, value) {
    const el = document.getElementById(id);
    if (el && value !== undefined) {
        el.textContent = value;
    }
}

function switchTab(tabName) {
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.tab === tabName);
    });
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.toggle('active', content.id === `tab-${tabName}`);
    });
}

function togglePasswordVisibility(inputId) {
    const input = document.getElementById(inputId);
    if (input) {
        input.type = input.type === 'password' ? 'text' : 'password';
    }
}

// File upload drag & drop
function initFileUpload() {
    const dropzone = document.getElementById('file-dropzone');
    const fileInput = document.getElementById('batch-file');

    if (!dropzone || !fileInput) return;

    dropzone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropzone.classList.add('dragover');
    });

    dropzone.addEventListener('dragleave', () => {
        dropzone.classList.remove('dragover');
    });

    dropzone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropzone.classList.remove('dragover');
        if (e.dataTransfer.files[0]) {
            fileInput.files = e.dataTransfer.files;
            updateFileLabel(e.dataTransfer.files[0].name);
        }
    });

    dropzone.addEventListener('click', () => fileInput.click());

    fileInput.addEventListener('change', () => {
        if (fileInput.files[0]) {
            updateFileLabel(fileInput.files[0].name);
        }
    });
}

function updateFileLabel(name) {
    const label = document.getElementById('file-label');
    if (label) label.textContent = name;
}

// Create floating particles
function createParticles(container, count = 20) {
    const el = document.getElementById(container);
    if (!el) return;

    for (let i = 0; i < count; i++) {
        const particle = document.createElement('div');
        particle.className = 'particle';
        particle.style.left = Math.random() * 100 + '%';
        particle.style.animationDelay = Math.random() * 6 + 's';
        particle.style.animationDuration = (5 + Math.random() * 5) + 's';
        el.appendChild(particle);
    }
}

// Navbar scroll effect
function initNavbar() {
    const navbar = document.querySelector('.navbar');
    if (!navbar) return;

    window.addEventListener('scroll', () => {
        navbar.classList.toggle('scrolled', window.scrollY > 10);
    });
}

// Update navbar user info
function updateNavUser() {
    const user = getUser();
    const userBadge = document.getElementById('nav-user-badge');
    if (userBadge && user) {
        userBadge.textContent = user.username;
    }
}


// ============================================================
// Results page initialization
// ============================================================

function initResultsPage() {
    const stored = sessionStorage.getItem('prediction_result');
    if (stored) {
        const prediction = JSON.parse(stored);
        animateGauge(prediction);
    }
}


// ============================================================
// Page Initialization
// ============================================================

document.addEventListener('DOMContentLoaded', () => {
    initNavbar();
    updateNavUser();

    // Page-specific initialization
    const page = document.body.dataset.page;

    switch (page) {
        case 'dashboard':
            loadDashboard();
            createParticles('dashboard-particles', 15);
            break;
        case 'predict':
            buildPredictForm();
            initFileUpload();
            break;
        case 'results':
            initResultsPage();
            break;
        case 'analytics':
            loadAnalytics();
            break;
    }
});
