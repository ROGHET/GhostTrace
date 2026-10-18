/**
 * GhostTrace — Frontend Interaction Controller
 * Modular Vanilla JS for UI controls, table searching, hash copying, and AJAX actions.
 */

document.addEventListener('DOMContentLoaded', () => {
    'use strict';

    // ── Sidebar Toggle & Persistence ─────────────────────────────────────────
    const sidebar = document.getElementById('sidebar');
    const sidebarToggle = document.getElementById('sidebar-toggle');

    if (sidebarToggle && sidebar) {
        // Restore state
        const savedState = localStorage.getItem('ghosttrace_sidebar_collapsed');
        if (savedState === 'true') {
            sidebar.classList.add('collapsed');
        }

        sidebarToggle.addEventListener('click', () => {
            sidebar.classList.toggle('collapsed');
            localStorage.setItem('ghosttrace_sidebar_collapsed', sidebar.classList.contains('collapsed'));
        });
    }

    // ── Global Search Filter ─────────────────────────────────────────────────
    const searchInput = document.getElementById('global-search');
    const searchableTables = document.querySelectorAll('.cyber-table[data-searchable="true"]');
    const searchableCards = document.querySelectorAll('.searchable-item');

    if (searchInput) {
        searchInput.addEventListener('input', (e) => {
            const query = e.target.value.toLowerCase().trim();

            // Filter searchable tables
            searchableTables.forEach(table => {
                const rows = table.querySelectorAll('tbody tr');
                rows.forEach(row => {
                    const text = row.textContent.toLowerCase();
                    row.style.display = text.includes(query) ? '' : 'none';
                });
            });

            // Filter searchable cards (findings, timeline)
            searchableCards.forEach(card => {
                const text = card.textContent.toLowerCase();
                card.style.display = text.includes(query) ? '' : 'none';
            });
        });
    }

    // ── Copy to Clipboard ────────────────────────────────────────────────────
    document.addEventListener('click', (e) => {
        const copyBtn = e.target.closest('[data-copy-target]');
        if (!copyBtn) return;

        const targetId = copyBtn.getAttribute('data-copy-target');
        const targetEl = document.getElementById(targetId);
        if (!targetEl) return;

        const textToCopy = targetEl.value || targetEl.textContent.trim();
        if (!textToCopy) return;

        navigator.clipboard.writeText(textToCopy).then(() => {
            showToast('success', 'Copied to Clipboard', `Digest recorded to system clipboard.`);
            const originalHtml = copyBtn.innerHTML;
            copyBtn.innerHTML = `
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <polyline points="20 6 9 17 4 12"></polyline>
                </svg>
                <span>Copied</span>
            `;
            setTimeout(() => {
                copyBtn.innerHTML = originalHtml;
            }, 2000);
        }).catch(err => {
            showToast('error', 'Clipboard Error', 'Could not copy to clipboard.');
        });
    });

    // ── Accordion Toggle for Findings ────────────────────────────────────────
    document.addEventListener('click', (e) => {
        const header = e.target.closest('.finding-header');
        if (!header) return;

        const item = header.closest('.finding-item');
        const body = item.querySelector('.finding-body');
        if (!body) return;

        const isExpanded = body.style.display === 'block';
        body.style.display = isExpanded ? 'none' : 'block';
        
        const arrow = header.querySelector('.finding-toggle-arrow');
        if (arrow) {
            arrow.style.transform = isExpanded ? 'rotate(0deg)' : 'rotate(90deg)';
        }
    });

    // ── Filter Buttons (Confidence, Category) ────────────────────────────────
    const filterButtons = document.querySelectorAll('[data-filter-group]');
    filterButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const group = btn.getAttribute('data-filter-group');
            const value = btn.getAttribute('data-filter-value');

            // Toggle active style
            document.querySelectorAll(`[data-filter-group="${group}"]`).forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            // Apply filter
            const targetItems = document.querySelectorAll(`[data-filter-${group}]`);
            targetItems.forEach(item => {
                const itemVal = item.getAttribute(`data-filter-${group}`);
                if (value === 'all' || itemVal === value) {
                    item.style.display = '';
                } else {
                    item.style.display = 'none';
                }
            });
        });
    });
});

/**
 * Toast Notification System (NO EMOJIS)
 */
function showToast(type, title, message, duration = 4000) {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;

    let iconSvg = '';
    if (type === 'success') {
        iconSvg = `
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
                <polyline points="22 4 12 14.01 9 11.01"></polyline>
            </svg>
        `;
    } else if (type === 'error') {
        iconSvg = `
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="10"></circle>
                <line x1="15" y1="9" x2="9" y2="15"></line>
                <line x1="9" y1="9" x2="15" y2="15"></line>
            </svg>
        `;
    } else {
        iconSvg = `
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="10"></circle>
                <line x1="12" y1="8" x2="12" y2="12"></line>
                <line x1="12" y1="16" x2="12.01" y2="16"></line>
            </svg>
        `;
    }

    toast.innerHTML = `
        <div class="toast-icon">${iconSvg}</div>
        <div class="toast-content">
            <div class="toast-title">${title}</div>
            <div class="toast-message">${message}</div>
        </div>
    `;

    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100%)';
        toast.style.transition = 'all 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, duration);
}
