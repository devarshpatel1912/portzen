// PortZen Monitoring and Scanner Control
function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `alert alert-${type} alert-dismissible fade show shadow-sm`;
    toast.role = 'alert';
    toast.innerHTML = `
        <span>${message}</span>
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    `;
    container.appendChild(toast);
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 250);
    }, 4500);
}

document.addEventListener('DOMContentLoaded', () => {
    // Handle on-demand Scan Now buttons
    const scanBtns = document.querySelectorAll('.btn-scan-now');
    scanBtns.forEach(btn => {
        btn.addEventListener('click', async (e) => {
            e.preventDefault();
            const hostId = btn.dataset.hostId;
            if (!hostId) return;

            const originalHtml = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1" role="status"></span> Scanning...';

            try {
                const response = await fetch(`/hosts/${hostId}/scan`, {
                    method: 'POST',
                    headers: { 'Accept': 'application/json' }
                });
                const result = await response.json();
                if (result.success) {
                    showToast(result.message, 'success');
                    // Reload after short delay to refresh all table rows & data
                    setTimeout(() => window.location.reload(), 800);
                } else {
                    showToast(result.error || 'Scan failed', 'danger');
                    btn.disabled = false;
                    btn.innerHTML = originalHtml;
                }
            } catch (err) {
                showToast('Network error while running scan', 'danger');
                btn.disabled = false;
                btn.innerHTML = originalHtml;
            }
        });
    });

    // Handle Create Baseline buttons
    const baselineBtns = document.querySelectorAll('.btn-create-baseline');
    baselineBtns.forEach(btn => {
        btn.addEventListener('click', async (e) => {
            e.preventDefault();
            const hostId = btn.dataset.hostId;
            if (!hostId) return;

            if (!confirm('Snapshot all currently listening ports as the approved baseline?')) {
                return;
            }

            const originalHtml = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1" role="status"></span> Saving Baseline...';

            try {
                const response = await fetch(`/hosts/${hostId}/baseline/create`, {
                    method: 'POST',
                    headers: { 'Accept': 'application/json' }
                });
                const result = await response.json();
                if (result.success) {
                    showToast(result.message, 'success');
                    setTimeout(() => window.location.reload(), 700);
                } else {
                    showToast(result.error || 'Failed to create baseline', 'danger');
                    btn.disabled = false;
                    btn.innerHTML = originalHtml;
                }
            } catch (err) {
                showToast('Network error while saving baseline', 'danger');
                btn.disabled = false;
                btn.innerHTML = originalHtml;
            }
        });
    });

    // Handle Start/Stop Monitoring toggles
    const toggleMonBtns = document.querySelectorAll('.btn-toggle-monitor');
    toggleMonBtns.forEach(btn => {
        btn.addEventListener('click', async (e) => {
            e.preventDefault();
            const hostId = btn.dataset.hostId;
            const action = btn.dataset.action; // 'start' or 'stop'
            if (!hostId || !action) return;

            const endpoint = `/hosts/${hostId}/monitor/${action}`;
            btn.disabled = true;

            try {
                const response = await fetch(endpoint, {
                    method: 'POST',
                    headers: { 'Accept': 'application/json' }
                });
                const result = await response.json();
                if (result.success) {
                    showToast(result.message, action === 'start' ? 'success' : 'info');
                    setTimeout(() => window.location.reload(), 600);
                } else {
                    showToast(result.error || 'Action failed', 'danger');
                    btn.disabled = false;
                }
            } catch (err) {
                showToast('Network error triggering monitoring', 'danger');
                btn.disabled = false;
            }
        });
    });
});
