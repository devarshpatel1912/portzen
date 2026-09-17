// PortZen Alert Management
document.addEventListener('DOMContentLoaded', () => {
    // 1. Alert Action Buttons (Acknowledge, Resolve, Ignore)
    const actionBtns = document.querySelectorAll('.btn-alert-action');

    actionBtns.forEach(btn => {
        btn.addEventListener('click', async (e) => {
            e.preventDefault();
            const alertId = btn.dataset.alertId;
            const action = btn.dataset.action; // acknowledge, resolve, ignore
            if (!alertId || !action) return;

            const originalText = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '...';

            try {
                const response = await fetch(`/alerts/${alertId}/${action}`, {
                    method: 'POST',
                    headers: { 'Accept': 'application/json' }
                });
                const result = await response.json();

                if (result.success) {
                    if (typeof showToast === 'function') {
                        showToast(result.message, action === 'resolve' ? 'success' : 'info');
                    }
                    // Update badge or card if on list or detail page
                    const card = document.getElementById(`alert-card-${alertId}`);
                    if (card && action === 'resolve') {
                        card.style.opacity = '0.5';
                    }
                    setTimeout(() => window.location.reload(), 500);
                } else {
                    alert(result.error || 'Action failed');
                    btn.disabled = false;
                    btn.innerHTML = originalText;
                }
            } catch (err) {
                alert('Network error updating alert status');
                btn.disabled = false;
                btn.innerHTML = originalText;
            }
        });
    });

    // 2. Client-Side Sorting Engine for Alert Cards
    function sortAlertCards(sortBy) {
        const container = document.querySelector('.security-alerts-container');
        if (!container) return;

        const cards = Array.from(container.querySelectorAll('.security-alert-item'));
        if (cards.length <= 1) return;

        cards.sort((a, b) => {
            const idA = parseInt(a.dataset.id || '0', 10);
            const idB = parseInt(b.dataset.id || '0', 10);
            const timeA = a.dataset.created ? new Date(a.dataset.created).getTime() : idA;
            const timeB = b.dataset.created ? new Date(b.dataset.created).getTime() : idB;
            const riskMap = { 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1 };
            const riskA = riskMap[a.dataset.risk] || 0;
            const riskB = riskMap[b.dataset.risk] || 0;

            if (sortBy === 'oldest') {
                return (timeA - timeB) || (idA - idB);
            } else if (sortBy === 'risk_high') {
                return (riskB - riskA) || (timeB - timeA) || (idB - idA);
            } else if (sortBy === 'risk_low') {
                return (riskA - riskB) || (timeB - timeA) || (idB - idA);
            } else {
                // newest
                return (timeB - timeA) || (idB - idA);
            }
        });

        // Re-append cards in sorted order
        cards.forEach(card => container.appendChild(card));
    }

    // Determine current sort mode from URL or active dropdown
    const urlParams = new URLSearchParams(window.location.search);
    const activeSort = urlParams.get('sort') || 'newest';

    // Apply sorting immediately on load to ensure instant visual ordering
    sortAlertCards(activeSort);

    // Support instant client-side reordering on clicking sort dropdown options
    const sortDropdownItems = document.querySelectorAll('.alert-sort-dropdown .dropdown-item');
    sortDropdownItems.forEach(item => {
        item.addEventListener('click', (e) => {
            const sortVal = item.dataset.sortVal;
            if (sortVal) {
                sortAlertCards(sortVal);
                const label = document.getElementById('currentSortLabel');
                if (label) {
                    label.textContent = item.querySelector('span') ? item.querySelector('span').textContent.trim() : sortVal;
                }
            }
        });
    });
});

