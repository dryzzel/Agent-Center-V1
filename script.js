const CONFIG = {
  // If running locally (localhost, 127.0.0.1) or via file protocol (opening index.html directly),
  // use the local server URL. Otherwise (production), use relative path.
  API_BASE_URL: (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1' || window.location.protocol === 'file:')
    ? 'http://localhost:3000'
    : '',
};

// Global Fetch Interceptor to handle Session Expiry (401)
const originalFetch = window.fetch;
window.fetch = async function (...args) {
  try {
    const response = await originalFetch(...args);
    if (response.status === 401) {
      // Check if we are already logging in to avoid loop
      const loginScreen = document.getElementById('loginScreen');
      if (loginScreen && loginScreen.style.display === 'none') {
        console.warn("Session expired (401). logging out...");
        if (typeof logout === 'function') {
          logout();
          if (typeof showToast === 'function')
            showToast("Session expired. Please login again.", "error");
        }
      }
    }
    return response;
  } catch (err) {
    throw err;
  }
};


// ==========================================
// LÓGICA DEL CLIENTE (FRONTEND)
// ==========================================
// Este archivo maneja toda la interactividad de la aplicación:
// 1. Conexión con Backend y WebSockets
// 2. Gestión de Estado (Usuario, Leads, Filtros)
// 3. Renderizado de UI (Tablas, Gráficos, Modales)
// 4. Lógica de Negocio (Asignación, Disposiciones)
// ==========================================

const socket = io(CONFIG.API_BASE_URL);

socket.on('connect', () => {
  console.log('Connected to Socket.io server');
});

// --- Conexión WebSocket ---
// Escucha eventos en tiempo real para actualizar la interfaz sin recargar.
socket.on('lead_updated', (data) => {
  console.log('Lead updated:', data);
  // Si el admin está activo, refrescar dashboards para mostrar datos nuevos al instante.
  if (document.getElementById('adminScreen').style.display !== 'none') {
    loadAnalyticsDashboard();
    loadUsersSummary();
  }
});

let currentUser = null;
let userToken = null;
let data = [];
let filteredData = [];
let isFilterActive = false;
let selectedDispositions = [];
let availableDispositions = [];
let currentIndex = 0;
let historyLog = [];
let sessionDispositions = {};
let lastSavedIndex = -1;

// ==========================================
// DEFINICIÓN DE FUNCIONES
// ==========================================

// Gestiona la navegación de la SPA (Single Page Application).
// Muestra la pantalla solicitada y oculta las demás.
function showScreen(id) {
  document.querySelectorAll('.screen').forEach(s => s.style.display = 'none');
  const displayType = (id === 'appScreen') ? 'grid' : (id === 'loginScreen' ? 'flex' : 'block');
  document.getElementById(id).style.display = displayType;
  feather.replace();
}

function showToast(message, type = 'info') {
  let backgroundColor;
  if (type === 'success') backgroundColor = "var(--success)";
  else if (type === 'error') backgroundColor = "var(--danger)";
  else backgroundColor = "var(--accent)";

  Toastify({
    text: message,
    duration: 3000,
    gravity: "top",
    position: "right",
    backgroundColor: backgroundColor,
    stopOnFocus: true,
    className: "notification",
    style: {
      background: backgroundColor,
      color: "#fff",
      boxShadow: "var(--shadow-lg)"
    }
  }).showToast();
}

// Cambia entre modo claro y oscuro, y guarda la preferencia en localStorage.
function toggleDarkMode() {
  document.body.classList.toggle('light-mode');
  const isLight = document.body.classList.contains('light-mode');
  localStorage.setItem('theme', isLight ? 'light' : 'dark');
  document.getElementById('themeToggleBtn').textContent = isLight ? '☀️' : '🌙';

  // Refresh charts if admin screen is visible
  if (document.getElementById('adminScreen').style.display !== 'none') {
    loadAnalyticsDashboard();
  }
  // If agent profile modal is open, refresh that too
  if (document.getElementById('agentProfileModal').style.display !== 'none') {
    getAgentStats();
  }
}

// Initialize Theme
const savedTheme = localStorage.getItem('theme');
if (savedTheme === 'light') {
  document.body.classList.add('light-mode');
  document.getElementById('themeToggleBtn').textContent = '☀️';
}
document.getElementById('themeToggleBtn').addEventListener('click', toggleDarkMode);

// Función de utilidad para prevenir ataques XSS (Cross-Site Scripting).
// Escapa caracteres especiales antes de renderizarlos en el HTML.
function escapeHtml(s) {
  if (s === null || s === undefined) return '';
  return String(s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; });
}

function phoneTelHref(raw) {
  const digits = (raw || "").toString().replace(/[^+0-9]/g, '');
  return `tel:${encodeURIComponent(digits)}`;
}

// ==========================================
// FUNCIONES DE ADMINISTRADOR
// ==========================================
// Inicialización del dashboard, gestión de usuarios y visualización de métricas.

async function initializeAdminHub() {
  document.getElementById('adminRefreshBtn').addEventListener('click', async () => {
    try {
      showToast('Refreshing dashboard...', 'info');
      await Promise.all([
        loadUsersSummary(),
        loadAnalyticsDashboard()
      ]);
      showToast('Dashboard updated', 'success');
    } catch (err) {
      console.error("Refresh failed", err);
      showToast('Failed to refresh', 'error');
    }
  });
  document.getElementById('adminLogoutBtn').addEventListener('click', logout);
  document.getElementById('createUserBtn').addEventListener('click', createNewUser);
  document.getElementById('saveUserChangesBtn').addEventListener('click', handleUpdateUser);
  document.getElementById('saveUserChangesBtn').addEventListener('click', handleUpdateUser);
  document.getElementById('closeModalBtn').addEventListener('click', closeEditModal);

  // New Admin Listeners
  document.getElementById('saveLeadChangesBtn').addEventListener('click', saveLeadChanges);
  document.getElementById('closeAdminEditModalBtn').addEventListener('click', () => document.getElementById('adminEditLeadModal').style.display = 'none');
  document.getElementById('confirmDeleteDuplicatesBtn').addEventListener('click', confirmDeleteDuplicates);
  document.getElementById('closeDuplicateModalBtn').addEventListener('click', () => document.getElementById('duplicatePreviewModal').style.display = 'none');

  document.getElementById('upload-leads-btn').addEventListener('click', uploadLeads);
  document.getElementById('getAgentStatsBtn').addEventListener('click', getAgentStats);
  document.getElementById('closeProfileModalBtn').addEventListener('click', () => document.getElementById('agentProfileModal').style.display = 'none');

  // Upload Info Modal Listeners
  document.getElementById('upload-info-btn').addEventListener('click', () => {
    document.getElementById('uploadInfoModal').style.display = 'flex';
    feather.replace();
  });
  document.getElementById('closeInfoModalBtn').addEventListener('click', () => {
    document.getElementById('uploadInfoModal').style.display = 'none';
  });

  await loadUsersSummary();
  const users = await getUsersSummary();
  const agentUsers = users.filter(user => user.role === 'agent');

  // Manual load only to save API calls
  document.getElementById('rcRefreshBtn').addEventListener('click', () => {
    const range = document.getElementById('rcTimeRange').value;
    loadRingCentralMetrics(range);
  });

  // Recalculate metrics when hours worked changes
  document.getElementById('rcHoursWorked').addEventListener('change', () => {
    const hours = document.getElementById('rcHoursWorked').value;
    localStorage.setItem('rcHoursWorked', hours);
    const savedData = localStorage.getItem('rcMetricsData');
    if (savedData) {
      try {
        renderRingCentralMetrics(JSON.parse(savedData));
      } catch (e) {
        console.error('Error parsing saved RC data', e);
      }
    }
  });

  // Restore saved RC metrics from localStorage
  const savedData = localStorage.getItem('rcMetricsData');
  const savedTimeRange = localStorage.getItem('rcMetricsTimeRange');
  const savedHoursWorked = localStorage.getItem('rcHoursWorked');

  if (savedHoursWorked) {
    document.getElementById('rcHoursWorked').value = savedHoursWorked;
  }

  if (savedData) {
    try {
      const data = JSON.parse(savedData);
      renderRingCentralMetrics(data);

      // Restore the time range selector
      if (savedTimeRange) {
        document.getElementById('rcTimeRange').value = savedTimeRange;
      }
    } catch (e) {
      console.error('Error loading saved RC metrics:', e);
    }
  }

  loadAnalyticsDashboard();
  // loadRingCentralMetrics(); // Removed auto-load
  initializeLeadManagement(agentUsers);
}

function openAgentProfile(userId, username) {
  document.getElementById('agentProfileId').value = userId;
  document.getElementById('agentProfileTitle').innerHTML = `<i data-feather="user"></i> Profile: ${escapeHtml(username)}`;
  feather.replace();

  // Set default dates (last 7 days)
  const endDate = new Date();
  const startDate = new Date();
  startDate.setDate(endDate.getDate() - 7);
  document.getElementById('statsStartDate').value = startDate.toISOString().split('T')[0];
  document.getElementById('statsEndDate').value = endDate.toISOString().split('T')[0];

  document.getElementById('agentStatsContainer').style.display = 'none';
  document.getElementById('agentProfileModal').style.display = 'flex';
}

let agentChart = null;

// Obtiene y visualiza las estadísticas detalladas de un agente (Perfil).
// Genera un gráfico de dona con las disposiciones y muestra métricas de eficiencia.
async function getAgentStats() {
  const userId = document.getElementById('agentProfileId').value;
  const startDate = document.getElementById('statsStartDate').value;
  const endDate = document.getElementById('statsEndDate').value;

  if (!startDate || !endDate) {
    showToast('Please select both a start and end date.');
    return;
  }

  try {
    const resp = await fetch(`${CONFIG.API_BASE_URL}/admin/users/${userId}/stats?startDate=${startDate}&endDate=${endDate}`, {
      headers: { 'Authorization': `Bearer ${userToken}` }
    });

    if (!resp.ok) {
      const err = await resp.json();
      showToast(`Error fetching stats: ${err.error}`);
      return;
    }

    const stats = await resp.json();
    console.log('Stats received from backend:', stats);

    document.getElementById('statsTotalCalls').textContent = stats.totalCalls;
    document.getElementById('statsContactRate').textContent = `${stats.contactRate.toFixed(1)}%`;
    document.getElementById('statsLeadConversion').textContent = `${stats.leadConversionRate.toFixed(1)}%`;

    const ctx = document.getElementById('agentDispositionChart').getContext('2d');
    if (agentChart) {
      agentChart.destroy();
    }
    const style = getComputedStyle(document.body);
    const textColor = style.getPropertyValue('--chart-text').trim();

    agentChart = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: Object.keys(stats.dispositions),
        datasets: [{
          label: 'Dispositions',
          data: Object.values(stats.dispositions),
          backgroundColor: [
            '#2962ff', '#f50057', '#00e676', '#651fff', '#ffea00', '#ff3d00',
            '#00b0ff', '#d500f9', '#1de9b6', '#ff9100', '#ff1744', '#3d5afe'
          ],
          borderColor: style.getPropertyValue('--card').trim(),
          borderWidth: 2
        }]
      },
      options: {
        responsive: true,
        plugins: {
          legend: { position: 'right', labels: { color: textColor, font: { family: 'Inter' } } },
          title: { display: true, text: 'Dispositions in Period', color: textColor, font: { family: 'Inter', size: 16 } }
        }
      }
    });

    document.getElementById('agentStatsContainer').style.display = 'block';

    // Populate numeric stats grid
    const statsList = document.getElementById('agentDispositionStatsList');
    statsList.innerHTML = '';
    Object.entries(stats.dispositions).forEach(([disposition, count]) => {
      const card = document.createElement('div');
      card.className = 'stat-card';
      card.innerHTML = `
        <h4 class="stat-title">${disposition}</h4>
        <p class="stat-value">${count}</p>
      `;
      statsList.appendChild(card);
    });

  } catch (err) {
    console.error('Error fetching agent stats:', err);
    showToast('A connection error occurred while fetching stats.');
  }
}

// Inicializa la gestión de leads: filtros, tabla de datos y acciones masivas.
function initializeLeadManagement(agentUsers) {
  const agentFilterSelect = document.getElementById('lead-filter-agent');
  const reassignAgentSelect = document.getElementById('reassign-lead-agent');

  const agentOptions = agentUsers.map(user => `<option value="${user.id}">${user.username}</option>`).join('');
  agentFilterSelect.innerHTML += agentOptions;
  reassignAgentSelect.innerHTML = `<option value="unassigned">Unassign (Back to Pool)</option>` + agentOptions;

  document.getElementById('filter-leads-btn').addEventListener('click', loadAllLeads);
  document.getElementById('reassign-selected-leads-btn').addEventListener('click', reassignSelectedLeads);

  // Enhanced Delete Button Logic
  document.getElementById('deduplicate-leads-btn').addEventListener('click', () => {
    document.getElementById('deleteOptionsModal').style.display = 'flex';
    feather.replace();
  });

  document.getElementById('closeDeleteOptionsModalBtn').addEventListener('click', () => {
    document.getElementById('deleteOptionsModal').style.display = 'none';
  });

  document.getElementById('btnDeleteDuplicates').addEventListener('click', () => {
    document.getElementById('deleteOptionsModal').style.display = 'none';
    handleDeduplicateLeads();
  });

  document.getElementById('btnDeleteSelected').addEventListener('click', () => {
    document.getElementById('deleteOptionsModal').style.display = 'none';
    deleteSelectedLeads();
  });

  // Obtiene las disposiciones únicas de los leads y construye el dropdown personalizado con checkboxes.
  // Permite filtrar por múltiples disposiciones a la vez.
  fetch(`${CONFIG.API_BASE_URL}/admin/leads`, { headers: { 'Authorization': `Bearer ${userToken}` } })
    .then(res => res.json())
    .then(leads => {
      const dispositions = [...new Set(['Sale', ...leads.map(lead => lead.DISPOSITION).filter(d => d)])].sort();
      const dropdownContent = document.getElementById('disposition-dropdown-content');
      const dropdownBtn = document.getElementById('disposition-dropdown-btn');
      const dropdownBtnText = dropdownBtn.querySelector('span');

      // Toggle dropdown
      dropdownBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        document.getElementById('disposition-dropdown-content').classList.toggle('show');
      });

      // Close dropdown when clicking outside
      document.addEventListener('click', (e) => {
        if (!e.target.closest('.custom-dropdown')) {
          document.getElementById('disposition-dropdown-content').classList.remove('show');
        }
      });

      dropdownContent.innerHTML = dispositions.map(d => `
        <div class="dropdown-item">
          <input type="checkbox" id="dispo-${d}" value="${d}" class="disposition-checkbox">
          <label for="dispo-${d}">${d}</label>
        </div>
      `).join('');

      // Update button text on change
      dropdownContent.addEventListener('change', () => {
        const selected = Array.from(document.querySelectorAll('.disposition-checkbox:checked')).map(cb => cb.value);
        if (selected.length === 0) {
          dropdownBtnText.textContent = 'All Dispositions';
        } else if (selected.length === 1) {
          dropdownBtnText.textContent = selected[0];
        } else {
          dropdownBtnText.textContent = `${selected.length} Selected`;
        }
      });
    });

  // Fetch and populate Product and Prev. Company dropdowns
  fetch(`${CONFIG.API_BASE_URL}/admin/filters/options`, { headers: { 'Authorization': `Bearer ${userToken}` } })
    .then(res => res.json())
    .then(data => {
      const productSelect = document.getElementById('lead-filter-product');
      const companySelect = document.getElementById('lead-filter-prev-company');

      if (data.products && data.products.length) {
        data.products.forEach(p => {
          const opt = document.createElement('option');
          opt.value = p;
          opt.textContent = p;
          productSelect.appendChild(opt);
        });
      }

      if (data.companies && data.companies.length) {
        data.companies.forEach(c => {
          const opt = document.createElement('option');
          opt.value = c;
          opt.textContent = c;
          companySelect.appendChild(opt);
        });
      }

      if (data.customIds && data.customIds.length) {
        const customIdSelect = document.getElementById('lead-filter-custom-id');
        data.customIds.forEach(id => {
          const opt = document.createElement('option');
          opt.value = id;
          opt.textContent = id;
          customIdSelect.appendChild(opt);
        });
      }

      // Populate Upload List Name Dropdown
      const uploadListSelect = document.getElementById('upload-list-name');
      const uploadExistingOptions = Array.from(uploadListSelect.options).map(o => o.value);

      // Populate Filter List Dropdown
      const filterListSelect = document.getElementById('lead-filter-list');
      const filterExistingOptions = Array.from(filterListSelect.options).map(o => o.value);

      if (data.listNames && data.listNames.length) {
        data.listNames.forEach(name => {
          // Add to Upload Dropdown
          if (!uploadExistingOptions.includes(name)) {
            const opt = document.createElement('option');
            opt.value = name;
            opt.textContent = name;
            uploadListSelect.appendChild(opt);
          }
          // Add to Filter Dropdown
          if (!filterExistingOptions.includes(name)) {
            const opt = document.createElement('option');
            opt.value = name;
            opt.textContent = name;
            filterListSelect.appendChild(opt);
          }
        });
      }
    })
    .catch(err => console.error('Error fetching filter options:', err));

  // Handler for Add Custom List Button
  document.getElementById('add-custom-list-btn').addEventListener('click', () => {
    const newListName = prompt("Enter the name for the new list:");
    if (newListName && newListName.trim() !== "") {
      const select = document.getElementById('upload-list-name');
      const opt = document.createElement('option');
      opt.value = newListName.trim();
      opt.textContent = newListName.trim();
      opt.selected = true;
      select.appendChild(opt);
      showToast(`Custom list '${newListName}' added.`, 'success');
    }
  });
}

let allLeadsTable = null;
let adminLeadsData = []; // Store fetched leads for edit modal access

// Carga y renderiza la tabla principal de leads en el panel de admin.
// Aplica filtros (agente, disposición, fecha, búsqueda) y configura la paginación.
async function loadAllLeads() {
  const selectedDispositions = Array.from(document.querySelectorAll('.disposition-checkbox:checked')).map(cb => cb.value);
  const agentId = document.getElementById('lead-filter-agent').value;
  const product = document.getElementById('lead-filter-product').value;
  const listName = document.getElementById('lead-filter-list').value;
  const prevCompany = document.getElementById('lead-filter-prev-company').value;
  const sortOrder = document.getElementById('lead-sort-order').value;
  const startDate = document.getElementById('lead-filter-start-date').value;
  const endDate = document.getElementById('lead-filter-end-date').value;
  const search = document.getElementById('lead-filter-search').value;
  const customId = document.getElementById('lead-filter-custom-id').value;

  let queryString = new URLSearchParams();
  if (selectedDispositions.length > 0) {
    selectedDispositions.forEach(d => queryString.append('disposition', d));
  }
  if (agentId) queryString.append('assignedTo', agentId);
  if (product) queryString.append('product', product);
  if (listName) queryString.append('listName', listName);
  if (prevCompany) queryString.append('prevCompany', prevCompany);
  if (startDate) queryString.append('startDate', startDate);
  if (endDate) queryString.append('endDate', endDate);
  if (search) queryString.append('search', search);
  if (customId) queryString.append('customId', customId);
  queryString.append('sortBy', 'date');
  queryString.append('sortOrder', sortOrder);

  try {
    const resp = await fetch(`${CONFIG.API_BASE_URL}/admin/leads?${queryString.toString()}`, {
      headers: { 'Authorization': `Bearer ${userToken}` }
    });
    if (!resp.ok) {
      showToast('Error loading leads');
      return;
    }
    const leads = await resp.json();
    adminLeadsData = leads; // Store globally
    const list = document.getElementById('all-leads-list');

    if (allLeadsTable) {
      allLeadsTable.destroy();
    }

    list.innerHTML = '';

    if (!leads.length) {
      list.innerHTML = '<p style="text-align:center;color:var(--subtext);">No leads match the current filters.</p>';
      return;
    }

    const table = document.createElement('table');
    table.id = 'all-leads-table';
    list.appendChild(table);

    allLeadsTable = new DataTable(table, {
      data: {
        headings: ['<input type="checkbox" id="select-all-filtered-leads">', 'List', 'Name', 'Phone', 'Disposition', 'Callback Date', 'Agent', 'Product', 'Last Modified', 'Actions'],
        data: leads.map(lead => [
          `<input type="checkbox" class="filtered-lead-checkbox" value="${lead._id}">`,
          lead.listName || 'N/A',
          lead.Name || 'No Name',
          lead.Phone || 'No Phone',
          lead.DISPOSITION || 'N/A',
          lead.callbackDate ? new Date(lead.callbackDate).toLocaleString() : 'N/A',
          lead.agent ? lead.agent.username : 'Unassigned',
          lead.Product || 'N/A',
          lead.Timestamp ? new Date(lead.Timestamp).toLocaleString() : 'N/A',
          `<div style="display:flex; gap:5px;">
             <button class="small-btn" style="padding: 4px 8px; font-size: 0.75rem; color: var(--success); border-color: var(--success);" onclick="markAsSale('${lead._id}')" title="Mark as Sale">
               <i data-feather="dollar-sign" style="width: 12px; height: 12px;"></i>
             </button>
             <button class="small-btn secondary" style="padding: 4px 8px; font-size: 0.75rem;" onclick="openAdminEditLeadModal('${lead._id}')" title="Edit Lead">
               <i data-feather="edit-2" style="width: 12px; height: 12px;"></i>
             </button>
           </div>`
        ])
      },
      perPage: 10,
      perPageSelect: [10, 20, 50, 100],
      searchable: true,
      sortable: true,
    });

    // Re-initialize feather icons after table render
    allLeadsTable.on('datatable.page', () => feather.replace());
    allLeadsTable.on('datatable.sort', () => feather.replace());
    allLeadsTable.on('datatable.perpage', () => feather.replace());
    allLeadsTable.on('datatable.search', () => feather.replace());
    feather.replace();

    document.getElementById('select-all-filtered-leads').addEventListener('change', (e) => {
      document.querySelectorAll('.filtered-lead-checkbox').forEach(checkbox => {
        checkbox.checked = e.target.checked;
      });
    });

  } catch (err) {
    console.error('Error loading all leads:', err);
    showToast('Connection error while loading leads.');
  }
}

// Marca un lead específico como 'Sale' (Venta) directamente desde la tabla.
async function markAsSale(leadId) {
  if (!confirm('Are you sure you want to mark this lead as a Sale?')) return;

  try {
    const resp = await fetch(`${CONFIG.API_BASE_URL}/admin/leads/${leadId}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${userToken}`
      },
      body: JSON.stringify({ DISPOSITION: 'Sale' })
    });

    const result = await resp.json();

    if (resp.ok && result.success) {
      showToast('Lead marked as Sale successfully', 'success');
      loadAllLeads(); // Refresh table
    } else {
      showToast(`Error: ${result.error || 'Could not update lead'}`, 'error');
    }
  } catch (err) {
    console.error('Error marking lead as sale:', err);
    showToast('Connection error while updating lead', 'error');
  }
}

// Reasigna los leads seleccionados a un nuevo agente o los desasigna (devuelve al pool).
async function reassignSelectedLeads() {
  const newUserId = document.getElementById('reassign-lead-agent').value;
  const selectedLeads = Array.from(document.querySelectorAll('.filtered-lead-checkbox:checked')).map(cb => cb.value);

  if (!newUserId) {
    showToast('Please select an agent to reassign the leads to.');
    return;
  }

  if (!selectedLeads.length) {
    showToast('Please select at least one lead to reassign.');
    return;
  }

  const action = newUserId === 'unassigned' ? 'unassign' : 'reassign';
  if (!confirm(`You are about to ${action} ${selectedLeads.length} leads. Are you sure?`)) {
    return;
  }

  try {
    const resp = await fetch(`${CONFIG.API_BASE_URL}/admin/leads/reassign`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${userToken}`
      },
      body: JSON.stringify({ leadIds: selectedLeads, newUserId })
    });

    const result = await resp.json();

    if (resp.ok && result.success) {
      showToast(result.message);
      loadAllLeads(); // Refresh the table
      loadUsersSummary(); // Refresh user stats
    } else {
      showToast(`Error: ${result.error || 'Could not reassign leads.'}`);
    }
  } catch (err) {
    showToast('Connection error while reassigning leads.');
  }
}

async function requestPasswordConfirmation() {
  return new Promise((resolve, reject) => {
    const modal = document.getElementById('passwordConfirmationModal');
    const input = document.getElementById('confirmActionPassword');
    const confirmBtn = document.getElementById('btnConfirmPassword');
    const cancelBtn = document.getElementById('btnClosePasswordModal');

    modal.style.display = 'flex';
    input.value = '';
    input.focus();

    const cleanup = () => {
      modal.style.display = 'none';
      confirmBtn.removeEventListener('click', onConfirm);
      cancelBtn.removeEventListener('click', onCancel);
    };

    const onConfirm = () => {
      const password = input.value;
      if (!password) {
        showToast('Password is required', 'error');
        return;
      }
      cleanup();
      resolve(password);
    };

    const onCancel = () => {
      cleanup();
      reject(new Error('Password confirmation cancelled'));
    };

    confirmBtn.addEventListener('click', onConfirm);
    cancelBtn.addEventListener('click', onCancel);
  });
}

async function deleteSelectedLeads() {
  const selectedLeads = Array.from(document.querySelectorAll('.filtered-lead-checkbox:checked')).map(cb => cb.value);

  if (!selectedLeads.length) {
    showToast('Please select at least one lead to delete.', 'error');
    return;
  }

  if (!confirm(`Are you sure you want to PERMANENTLY DELETE ${selectedLeads.length} leads? This action cannot be undone.`)) {
    return;
  }

  try {
    const password = await requestPasswordConfirmation();

    const resp = await fetch(`${CONFIG.API_BASE_URL}/admin/leads/bulk`, {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${userToken}`
      },
      body: JSON.stringify({ leadIds: selectedLeads, password })
    });

    const result = await resp.json();

    if (resp.ok && result.success) {
      showToast(result.message, 'success');
      loadAllLeads(); // Refresh table
      loadUsersSummary(); // Refresh stats
    } else {
      showToast(`Error: ${result.error || 'Delete failed'}`, 'error');
    }
  } catch (err) {
    if (err.message !== 'Password confirmation cancelled') {
      console.error('Error deleting leads:', err);
      showToast('Action cancelled or failed.', 'error');
    }
  }
}

// Open the Admin Edit Lead Modal
function openAdminEditLeadModal(leadId) {
  const lead = adminLeadsData.find(l => l._id === leadId);
  if (!lead) {
    showToast('Lead not found');
    return;
  }

  document.getElementById('editLeadId').value = lead._id;
  document.getElementById('editLeadName').value = lead.Name || '';
  document.getElementById('editLeadPhone').value = lead.Phone || '';
  document.getElementById('editLeadEmail').value = lead.Email || '';
  document.getElementById('editLeadProduct').value = lead.Product || '';
  document.getElementById('editLeadDisposition').value = lead.DISPOSITION || '';
  document.getElementById('editLeadPrevCompany').value = lead['Prev. Company'] || '';
  document.getElementById('editLeadListName').value = lead.listName || '';
  document.getElementById('editLeadAddress').value = lead.Address || '';

  // Render History
  const historyList = document.getElementById('adminLeadHistoryList');
  if (lead.history && lead.history.length > 0) {
    historyList.innerHTML = lead.history.slice().reverse().map(h => `
      <div style="border-bottom:1px solid var(--border); padding: 8px 0;">
        <div style="display:flex; justify-content:space-between; font-size:0.85em; color:var(--subtext);">
          <span>${new Date(h.timestamp).toLocaleString()}</span>
          <strong>${escapeHtml(h.disposition)}</strong>
        </div>
        <div style="font-size:0.9em; margin-top:2px;">${escapeHtml(h.note || h.action)}</div>
      </div>
    `).join('');
  } else {
    historyList.innerHTML = '<p style="text-align:center; color:var(--subtext);">No history available</p>';
  }

  document.getElementById('adminEditLeadModal').style.display = 'flex';
}

// Save changes from Admin Edit Lead Modal
async function saveLeadChanges() {
  const id = document.getElementById('editLeadId').value;
  const Name = document.getElementById('editLeadName').value;
  const Phone = document.getElementById('editLeadPhone').value;
  const Email = document.getElementById('editLeadEmail').value;
  const Product = document.getElementById('editLeadProduct').value;
  const DISPOSITION = document.getElementById('editLeadDisposition').value;
  const prevCompany = document.getElementById('editLeadPrevCompany').value;
  const listName = document.getElementById('editLeadListName').value;
  const Address = document.getElementById('editLeadAddress').value;

  try {
    const resp = await fetch(`${CONFIG.API_BASE_URL}/admin/leads/${id}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${userToken}`
      },
      body: JSON.stringify({
        Name, Phone, Email, Product, DISPOSITION,
        'Prev. Company': prevCompany,
        listName, Address
      })
    });

    const result = await resp.json();
    if (resp.ok && result.success) {
      showToast('Lead updated successfully', 'success');
      document.getElementById('adminEditLeadModal').style.display = 'none';
      loadAllLeads(); // Refresh table
    } else {
      showToast(`Error: ${result.error || 'Update failed'}`);
    }
  } catch (err) {
    console.error('Error updating lead:', err);
    showToast('Connection error');
  }
}

// Inicia el proceso de deduplicación de leads en el backend (PREVIEW).
async function handleDeduplicateLeads() {
  try {
    const resp = await fetch(`${CONFIG.API_BASE_URL}/admin/leads/deduplicate/preview`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${userToken}`
      }
    });

    const result = await resp.json();

    if (resp.ok) {
      if (result.count === 0) {
        showToast("No duplicate leads found.", "success");
        return;
      }

      // Show modal
      const list = document.getElementById('duplicatePreviewList');
      document.getElementById('duplicateCountMsg').textContent = `Found ${result.count} duplicate leads to be removed.`;

      list.innerHTML = result.preview.map(item => `
         <div style="padding: 10px; border-bottom: 1px solid var(--border);">
            <div style="font-weight:bold; color:var(--accent);">Phone: ${item.phone}</div>
            <div style="font-size:0.9em; margin-top:5px;">
               <span style="color:var(--success);">Keep (Newest):</span> 
               ${item.kept.Name || 'No Name'} (${new Date(item.kept.Timestamp || item.kept._id).toLocaleString()})
            </div>
            <div style="font-size:0.9em; margin-top:5px; color:var(--danger);">
               Delete (${item.removed.length}): 
            </div>
            <ul style="font-size:0.85em; color:var(--subtext); padding-left: 20px;">
               ${item.removed.map(r => `<li>${r.Name || 'No Name'} (${new Date(r.Timestamp || r._id).toLocaleString()})</li>`).join('')}
            </ul>
         </div>
       `).join('');

      document.getElementById('duplicatePreviewModal').style.display = 'flex';

    } else {
      showToast(`Error: ${result.error || 'Could not preview duplicates.'}`, 'error');
    }
  } catch (err) {
    console.error('Error previewing duplicates:', err);
    showToast('Connection error while previewing duplicates.', 'error');
  }
}

// Confirmar y ejecutar la eliminación de duplicados
async function confirmDeleteDuplicates() {
  try {
    const password = await requestPasswordConfirmation();

    const resp = await fetch(`${CONFIG.API_BASE_URL}/admin/leads/deduplicate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${userToken}`
      },
      body: JSON.stringify({ password })
    });

    const result = await resp.json();

    if (resp.ok && result.success) {
      showToast(result.message, 'success');
      document.getElementById('duplicatePreviewModal').style.display = 'none';
      loadAllLeads(); // Refresh the table
      loadUsersSummary(); // Refresh user stats if needed
    } else {
      showToast(`Error: ${result.error || result.message || 'Could not deduplicate leads.'}`, 'error');
    }
  } catch (err) {
    if (err.message !== 'Password confirmation cancelled') {
      console.error('Error deduplicating leads:', err);
      showToast('Connection error while deduplicating leads.', 'error');
    }
  }
}

window.unassignedLeadsTable = null;

// Carga la lista de leads que no tienen agente asignado.
async function loadUnassignedLeads() {
  try {
    const resp = await fetch(`${CONFIG.API_BASE_URL}/admin/leads/unassigned`, {
      headers: { 'Authorization': `Bearer ${userToken}` }
    });
    if (!resp.ok) {
      showToast('Error loading unassigned leads');
      return;
    }
    const leads = await resp.json();
    const list = document.getElementById('unassigned-leads-list');

    if (unassignedLeadsTable) {
      unassignedLeadsTable.destroy();
    }

    list.innerHTML = ''; // Clear previous content

    if (!leads.length) {
      list.innerHTML = '<p style="text-align:center;color:var(--subtext);">No unassigned leads</p>';
      return;
    }

    const table = document.createElement('table');
    table.id = 'unassigned-leads-table';
    list.appendChild(table);

    unassignedLeadsTable = new DataTable(table, {
      data: {
        headings: ['<input type="checkbox" id="select-all-leads">', 'Name', 'Phone', 'Product'],
        data: leads.map(lead => [
          `<input type="checkbox" class="lead-checkbox" value="${lead._id}">`,
          lead.Name || 'No Name',
          lead.Phone || 'No Phone',
          lead.Product || 'N/A'
        ])
      },
      perPage: 5,
      perPageSelect: [5, 10, 20, 50, 100],
      searchable: true,
      sortable: true,
    });

    document.getElementById('select-all-leads').addEventListener('change', (e) => {
      document.querySelectorAll('.lead-checkbox').forEach(checkbox => {
        checkbox.checked = e.target.checked;
      });
    });

  } catch (err) {
    console.error('Error loading unassigned leads:', err);
    showToast('Connection error while loading unassigned leads.');
  }
}



// Carga métricas de RingCentral y las guarda localmente para persistencia.
async function loadRingCentralMetrics(timeRange = 'today') {
  try {
    const resp = await fetch(`${CONFIG.API_BASE_URL}/admin/ringcentral/stats?timeRange=${timeRange}`, {
      headers: { 'Authorization': `Bearer ${userToken}` }
    });

    if (!resp.ok) {
      console.error('Error loading RC metrics');
      return;
    }

    const data = await resp.json();

    // Save to localStorage for persistence
    localStorage.setItem('rcMetricsData', JSON.stringify(data));
    localStorage.setItem('rcMetricsTimeRange', timeRange);

    // Render the data
    renderRingCentralMetrics(data);

  } catch (err) {
    console.error('Error loading RC metrics:', err);
  }
}

// Renderiza las métricas de RingCentral en el DOM (Globales y por Agente).
// Calcula métricas derivadas como llamadas por hora y tiempo entre llamadas.
function renderRingCentralMetrics(data) {
  const hoursWorked = parseInt(document.getElementById('rcHoursWorked').value) || 8;
  const secondsWorked = hoursWorked * 3600;

  // Update Global Stats
  document.getElementById('rcGlobalCallsPerHour').textContent = data.global.callsPerHour || '0';
  document.getElementById('rcGlobalTimeBetweenCalls').textContent = (data.global.avgTimeBetweenCalls || '0') + 's';

  // Update Agent Grid
  const container = document.getElementById('rcAgentMetrics');
  if (!container) return;

  if (!data.agents || data.agents.length === 0) {
    container.innerHTML = '<p style="grid-column: 1/-1; text-align: center; color: var(--subtext);">No RingCentral data available.</p>';
    return;
  }

  container.innerHTML = data.agents.map(agent => {
    const calls = agent.calls || 0;
    const duration = agent.duration || 0; // in seconds
    const durationMin = (duration / 60).toFixed(1);

    // Recalculate based on selected hours
    const callsPerHour = (calls / hoursWorked).toFixed(1);

    // Time Between Calls = (Total Time - Talk Time) / Total Calls
    let timeBetweenCalls = 0;
    if (calls > 0) {
      const availableTime = Math.max(0, secondsWorked - duration);
      timeBetweenCalls = (availableTime / calls).toFixed(0);
    }

    return `
    <div class="user-card">
      <div class="user-info">
        <div class="user-avatar">${agent.name.substring(0, 2).toUpperCase()}</div>
        <div>
          <div class="user-name">${escapeHtml(agent.name)}</div>
          <div class="user-role">Agent</div>
        </div>
      </div>
      <div class="stats-grid" style="grid-template-columns: 1fr 1fr; gap: 8px; margin-top: 12px;">
        <div class="stat-card" style="padding: 8px;">
          <h4 class="stat-title" style="font-size: 0.75rem;">Calls/Hr</h4>
          <p class="stat-value" style="font-size: 1.5rem;">${callsPerHour}</p>
          <small style="display:block; margin-top:4px; color:var(--subtext); font-size:0.9rem;">Total: ${calls}</small>
        </div>
        <div class="stat-card" style="padding: 8px;">
          <h4 class="stat-title" style="font-size: 0.75rem;">Time B/W Calls</h4>
          <p class="stat-value" style="font-size: 1.5rem;">${timeBetweenCalls}s</p>
          <small style="display:block; margin-top:4px; color:var(--subtext); font-size:0.9rem;">Dur: ${durationMin}m</small>
        </div>
      </div>
    </div>
  `}).join('');
}

// Maneja la subida del archivo CSV y refresca las listas tras el éxito.
async function uploadLeads() {
  const listName = document.getElementById('upload-list-name').value;
  const customId = document.getElementById('upload-custom-id').value.trim();
  const fileInput = document.getElementById('upload-csv-file');
  const file = fileInput.files[0];

  if (!customId) {
    showToast('Custom ID is required.', 'error');
    return;
  }

  if (!file) {
    showToast('Please select a CSV file.');
    return;
  }

  const formData = new FormData();
  formData.append('listName', listName);
  formData.append('customId', customId);
  formData.append('file', file);

  try {
    const resp = await fetch(`${CONFIG.API_BASE_URL}/admin/upload`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${userToken}`
      },
      body: formData
    });

    const result = await resp.json();

    if (resp.ok) {
      showToast(result.message);
      fileInput.value = ''; // Clear input
      loadUnassignedLeads(); // Refresh unassigned leads
      loadAllLeads(); // Refresh all leads table
    } else {
      showToast(`Error: ${result.error || 'Upload failed'}`);
    }
  } catch (err) {
    console.error('Error uploading leads:', err);
    showToast('Connection error while uploading leads.');
  }
}



// Carga el resumen de usuarios (Leaderboard y Tarjetas de Progreso).
async function loadUsersSummary() {
  const users = await getUsersSummary();
  const usersSummaryDiv = document.getElementById('usersSummary');
  const lastUpdateDiv = document.getElementById('lastUpdate');
  lastUpdateDiv.textContent = `Last update: ${new Date().toLocaleString()}`;
  if (!users.length) {
    usersSummaryDiv.innerHTML = '<p>No users registered.</p>';
    return;
  }
  usersSummaryDiv.innerHTML = users.map(user => {
    const stats = user.stats || {};
    const sinRespuesta = (stats.NA || 0) + (stats.VM || 0) + (stats.DC || 0);
    const leads = (stats.FUTURE || 0) + (stats['ND/SD'] || 0);
    const contactos = Object.keys(stats).reduce((acc, key) => {
      if (key !== 'NA' && key !== 'VM' && key !== 'DC') {
        return acc + stats[key];
      }
      return acc;
    }, 0);
    const progress = user.progress || { currentIndex: 0, total: 0 };
    const progressPercentage = progress.total > 0 ? (((progress.currentIndex + 1) / progress.total) * 100).toFixed(1) : 0;

    return `
    <div style="background:var(--bg);border:1px solid var(--border);padding:12px;border-radius:8px;">
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <div style="font-weight:700;color:var(--accent);">${escapeHtml(user.username)} ${user.role === 'admin' ? '(Admin)' : ''}</div>
        <small>${escapeHtml(user.email)}</small>
      </div>
      <div style="margin-top:10px;">
        <div style="font-weight:600;margin-bottom:5px;">Assigned List:</div>
        <div style="font-size:0.9em;color:var(--subtext);">${user.filename ? escapeHtml(user.filename) : 'None'}</div>
      </div>
      <div style="margin-top:10px;">
        <div style="font-weight:600;margin-bottom:5px;">List Progress:</div>
        <div style="background:var(--border);border-radius:4px;overflow:hidden;">
          <div style="background:var(--accent);width:${progressPercentage}%;padding:4px;text-align:center;color:white;font-size:0.8em;">${progressPercentage}%</div>
        </div>
        <div style="text-align:right;font-size:0.8em;color:var(--subtext);">${progress.currentIndex + 1} / ${progress.total}</div>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;margin-top:10px;">
        <div style="background:rgba(239, 68, 68, 0.1);padding:8px;border-radius:6px;text-align:center;"><div style="font-size:1.1em;font-weight:700;color:var(--danger);">${sinRespuesta}</div><div style="color:var(--subtext);font-size:0.9em;">No answer</div></div>
        <div style="background:rgba(16, 185, 129, 0.1);padding:8px;border-radius:6px;text-align:center;"><div style="font-size:1.1em;font-weight:700;color:var(--success);">${contactos}</div><div style="color:var(--subtext);font-size:0.9em;">Contacts</div></div>
        <div style="background:rgba(245, 158, 11, 0.1);padding:8px;border-radius:6px;text-align:center;"><div style="font-size:1.1em;font-weight:700;color:var(--warning);">${leads}</div><div style="color:var(--subtext);font-size:0.9em;">Leads</div></div>
      </div>
      <div style="margin-top:10px;font-size:0.8em;color:var(--subtext);">Last activity: ${new Date(user.lastActivity).toLocaleDateString()}</div>
      <div class="user-card-actions">
        <button class="small-btn" onclick="openAgentProfile('${user.id}', '${escapeHtml(user.username)}')"><i data-feather="bar-chart-2"></i> Profile</button>

        ${user.role !== 'admin' ?
        `<button class="small-btn secondary" onclick='openEditModal(${JSON.stringify(user)})'><i data-feather="edit"></i> Edit</button>
         <button class="small-btn danger-btn" onclick="handleDeleteUser('${user.id}')"><i data-feather="trash-2"></i> Delete</button>` : ''}
      </div>
    </div>`;
  }).join('');
  feather.replace();

  // Populate Leaderboard
  const agents = users.filter(u => u.role === 'agent');
  const sortedAgents = agents.sort((a, b) => {
    const statsA = a.stats || {};
    const statsB = b.stats || {};
    const leadsA = (statsA.FUTURE || 0) + (statsA['ND/SD'] || 0);
    const leadsB = (statsB.FUTURE || 0) + (statsB['ND/SD'] || 0);
    return leadsB - leadsA; // Descending order
  }).slice(0, 3); // Top 3

  const leaderboardDiv = document.getElementById('leaderboardContainer');
  if (!sortedAgents.length) {
    leaderboardDiv.innerHTML = '<p>No data for leaderboard yet.</p>';
  } else {
    leaderboardDiv.innerHTML = sortedAgents.map((agent, index) => {
      const stats = agent.stats || {};
      const leads = (stats.FUTURE || 0) + (stats['ND/SD'] || 0);
      const medals = ['🥇', '🥈', '🥉'];

      return `
      <div style="background:var(--card);border:1px solid var(--border);padding:16px;border-radius:8px;display:flex;align-items:center;gap:16px;box-shadow:var(--shadow);">
        <div style="font-size:2em;">${medals[index]}</div>
        <div>
          <div style="font-weight:700;font-size:1.1em;color:var(--text);">${escapeHtml(agent.username)}</div>
          <div style="color:var(--accent);font-weight:600;">${leads} Leads</div>
        </div>
      </div>`;
    }).join('');
  }
}

async function downloadUserList(userId) {
  // This function was removed, but it's not defined in the provided context.
  // Assuming it should download a user-specific list.
  // This is a placeholder implementation.
  showToast(`Placeholder: Downloading list for user ${userId}`);
}

async function getUsersSummary() {
  try {
    const resp = await fetch(`${CONFIG.API_BASE_URL}/admin/users`, { headers: { 'Authorization': `Bearer ${userToken}` } });
    if (!resp.ok) return [];
    return await resp.json();
  } catch (err) {
    console.error('Error getting user summary:', err);
    return [];
  }
}

// Crea un nuevo usuario (Agente) en el sistema.
async function createNewUser() {
  const username = document.getElementById('newUsername').value;
  const password = document.getElementById('newPassword').value;
  const email = document.getElementById('newEmail').value;
  if (!username || !password) {
    showToast('Username and password are required');
    return;
  }
  const result = await createUser({ username, password, email });
  if (result.success) {
    showToast(result.message);
    document.getElementById('newUsername').value = '';
    document.getElementById('newPassword').value = '';
    document.getElementById('newEmail').value = '';
    loadUsersSummary();
  } else {
    showToast('Error: ' + result.error);
  }
}

async function createUser(userData) {
  try {
    const resp = await fetch(`${CONFIG.API_BASE_URL}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${userToken}` },
      body: JSON.stringify(userData)
    });
    if (resp.ok) return { success: true, message: 'User created successfully' };
    const payload = await resp.json();
    return { success: false, error: payload.error || 'Error creating user' };
  } catch (err) {
    return { success: false, error: 'Connection error' };
  }
}

function openEditModal(user) {
  document.getElementById('editUserId').value = user.id;
  document.getElementById('editUserUsername').value = user.username;
  document.getElementById('editUserPassword').value = ''; // Reset password field
  document.getElementById('editUserEmail').value = user.email;
  document.getElementById('editUserRcExtensionId').value = user.rcExtensionId || '';
  document.getElementById('editUserRole').value = user.role;
  document.getElementById('editUserModal').style.display = 'flex';
  feather.replace();
}

function closeEditModal() {
  document.getElementById('editUserModal').style.display = 'none';
}

async function handleUpdateUser() {
  const userId = document.getElementById('editUserId').value;
  const username = document.getElementById('editUserUsername').value;
  const password = document.getElementById('editUserPassword').value;
  const email = document.getElementById('editUserEmail').value;
  const rcExtensionId = document.getElementById('editUserRcExtensionId').value;
  const role = document.getElementById('editUserRole').value;

  if (!role || !username) {
    showToast('Username and Role are required');
    return;
  }

  try {
    const resp = await fetch(`${CONFIG.API_BASE_URL}/admin/users/${userId}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${userToken}`
      },
      body: JSON.stringify({ email, role, username, password, rcExtensionId })
    });

    const result = await resp.json();

    if (resp.ok && result.success) {
      showToast(result.message);
      closeEditModal();
      loadUsersSummary();
    } else {
      showToast(`Error: ${result.error || 'Could not update user.'}`);
    }
  } catch (err) {
    showToast('Connection error while updating user.');
  }
}

async function handleDeleteUser(userId) {
  if (!confirm(`Are you sure you want to delete user with ID ${userId}? This action cannot be undone.`)) {
    return;
  }

  try {
    const resp = await fetch(`${CONFIG.API_BASE_URL}/admin/users/${userId}`, {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${userToken}`
      }
    });

    const result = await resp.json();

    if (resp.ok && result.success) {
      showToast(result.message);
      loadUsersSummary();
    } else {
      showToast(`Error: ${result.error || 'Could not delete user.'}`);
    }
  } catch (err) {
    showToast('Connection error while deleting user.');
  }
}

let unassignedLeadsTable;


// Carga el Dashboard de Analíticas Globales.
// Calcula métricas clave (Total Llamadas, Tasa de Contacto, Conversión) y renderiza gráficos.
async function loadAnalyticsDashboard() {
  try {
    const resp = await fetch(`${CONFIG.API_BASE_URL}/admin/stats`, {
      headers: { 'Authorization': `Bearer ${userToken}` }
    });
    if (!resp.ok) {
      console.error('Error fetching stats');
      return;
    }
    const stats = await resp.json();

    // Calculate Global Metrics
    const totalCalls = Object.values(stats).reduce((a, b) => a + b, 0);
    const nonContactDispos = ['NA', 'VM', 'DC', 'WN'];
    const leadDispos = ['FUTURE', 'ND/SD'];

    const totalContacts = Object.entries(stats)
      .filter(([key]) => !nonContactDispos.includes(key))
      .reduce((sum, [, value]) => sum + value, 0);

    const totalLeads = Object.entries(stats)
      .filter(([key]) => leadDispos.includes(key))
      .reduce((sum, [, value]) => sum + value, 0);

    const contactRate = totalCalls > 0 ? ((totalContacts / totalCalls) * 100).toFixed(1) : 0;
    const conversionRate = totalContacts > 0 ? ((totalLeads / totalContacts) * 100).toFixed(1) : 0;

    document.getElementById('globalTotalCalls').textContent = totalCalls;
    document.getElementById('globalContactRate').textContent = `${contactRate}%`;
    document.getElementById('globalConversionRate').textContent = `${conversionRate}%`;

    const statsList = document.getElementById('dispositionStatsList');
    statsList.innerHTML = '';

    Object.entries(stats).forEach(([disposition, count]) => {
      const card = document.createElement('div');
      card.className = 'stat-card';
      card.innerHTML = `
        <h4 class="stat-title">${disposition}</h4>
        <p class="stat-value">${count}</p>
      `;
      statsList.appendChild(card);
    });

    // Load Agent Performance
    loadAgentPerformanceChart();

  } catch (err) {
    console.error('Error loading analytics dashboard:', err);
  }
}

let performanceChart = null;

// Genera el gráfico de barras comparativo de Tasa de Conversión entre agentes.
async function loadAgentPerformanceChart() {
  try {
    const users = await getUsersSummary();
    const agents = users.filter(u => u.role === 'agent');

    const labels = agents.map(a => a.username);
    const conversionRates = agents.map(a => {
      // Calculate conversion rate from stats
      const stats = a.stats || {};
      const nonContactDispos = ['NA', 'VM', 'DC', 'WN'];
      const leadDispos = ['FUTURE', 'ND/SD'];

      const totalContacts = Object.entries(stats)
        .filter(([key]) => !nonContactDispos.includes(key))
        .reduce((sum, [, value]) => sum + value, 0);

      const totalLeads = Object.entries(stats)
        .filter(([key]) => leadDispos.includes(key))
        .reduce((sum, [, value]) => sum + value, 0);

      return totalContacts > 0 ? ((totalLeads / totalContacts) * 100).toFixed(1) : 0;
    });

    const ctx = document.getElementById('agentPerformanceChart').getContext('2d');

    if (performanceChart) {
      performanceChart.destroy();
    }

    const style = getComputedStyle(document.body);
    const textColor = style.getPropertyValue('--chart-text').trim();
    const gridColor = style.getPropertyValue('--chart-grid').trim();

    performanceChart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: labels,
        datasets: [{
          label: 'Conversion Rate (%)',
          data: conversionRates,
          backgroundColor: '#00e676',
          borderRadius: 4
        }]
      },
      options: {
        responsive: true,
        scales: {
          y: {
            beginAtZero: true,
            grid: { color: gridColor },
            ticks: { color: textColor }
          },
          x: {
            grid: { display: false },
            ticks: { color: textColor }
          }
        },
        plugins: {
          legend: { display: false },
          title: {
            display: true,
            text: 'Agent Conversion Rates',
            color: textColor,
            font: { family: 'Inter', size: 16 }
          }
        }
      }
    });

  } catch (err) {
    console.error('Error loading performance chart:', err);
  }
}

// ===== APP FUNCTIONS =====

// Inicializa la aplicación para el agente.
// Configura listeners de eventos, navegación y carga los datos iniciales.
function initializeApp() {
  document.getElementById('searchInput').addEventListener('input', (e) => performSearch(e.target.value));
  document.getElementById('nextBtn').addEventListener('click', nextRow);
  document.getElementById('prevBtn').addEventListener('click', prevRow);

  document.getElementById('exportSummaryBtn').addEventListener('click', exportSummaryTXT);
  document.getElementById('clearHistoryBtn').addEventListener('click', clearHistory);
  document.getElementById('goToRowBtn').addEventListener('click', goToRow);
  document.getElementById('clearDispositionBtn').addEventListener('click', clearDispositionData);
  document.getElementById('logoutBtn').addEventListener('click', logout);

  document.getElementById('toggleFilterBtn').addEventListener('click', toggleFilterPanel);
  document.getElementById('applyFilterBtn').addEventListener('click', applyFilter);
  document.getElementById('selectAllBtn').addEventListener('click', selectAllDispositions);
  document.getElementById('clearFilterBtn').addEventListener('click', clearFilter);
  document.getElementById('hideFilterBtn').addEventListener('click', hideFilterPanel);
  document.getElementById('toggleCallbacksBtn').addEventListener('click', toggleCallbacksPanel);
  document.getElementById('exportCallbacksBtn').addEventListener('click', exportCallbacks);
  document.getElementById('viewHistoryBtn').addEventListener('click', () => {
    const currentLead = isFilterActive ? filteredData[currentIndex] : data[currentIndex];
    if (currentLead && currentLead._id) {
      showHistory(currentLead._id);
    } else {
      showToast('No lead selected');
    }
  });

  document.getElementById('navigationContainer').style.display = 'block';
  document.getElementById('counterContainer').style.display = 'block';
  document.getElementById('clearDispositionBtn').style.display = 'block';
  document.getElementById('controls').style.display = 'flex';

  loadAgentData();
  loadUserData();
  loadCallbacks();

  // Export Summary Modal Listeners
  document.getElementById('closeExportSummaryModalBtn').addEventListener('click', () => {
    document.getElementById('exportSummaryModal').style.display = 'none';
  });

  document.getElementById('copySummaryBtn').addEventListener('click', () => {
    const content = document.getElementById('exportSummaryContent').textContent;
    navigator.clipboard.writeText(content).then(() => {
      showToast('Summary copied to clipboard', 'success');
    }).catch(err => {
      console.error('Copy error:', err);
      showToast('Failed to copy summary', 'error');
    });
  });

  // Lead Form Modal Listeners
  document.getElementById('openFormBtn').addEventListener('click', openLeadForm);
  document.getElementById('closeFormModalBtn').addEventListener('click', () => {
    document.getElementById('leadFormModal').style.display = 'none';
  });
  document.getElementById('addProductBtn').addEventListener('click', addProductRow);
  document.getElementById('copyFormBtn').addEventListener('click', copyFormToClipboard);
}



function updateCallbacksList(callbacks) {
  const list = document.getElementById('callbacksList');
  if (!callbacks.length) {
    list.innerHTML = '<p style="text-align:center;color:var(--subtext);">No pending callbacks</p>';
    return;
  }

  const now = new Date();

  list.innerHTML = callbacks
    .sort((a, b) => new Date(a.callback) - new Date(b.callback))
    .map(cb => {
      const cbDate = new Date(cb.callback);
      const isPast = cbDate < now;
      const timeDiff = Math.round((cbDate - now) / 1000 / 60);

      let timeString = '';
      if (isPast) {
        timeString = `${Math.abs(timeDiff)} minutes ago`;
      } else {
        timeString = `In ${timeDiff} minutes`;
      }

      return `
      <div class="filter-option" style="cursor:pointer;padding:8px;margin:2px 0;border-radius:4px;border:1px solid var(--border); ${isPast ? 'background-color: var(--danger-light);' : ''}" onclick="goToCallback('${cb._id}')">
        <strong>${escapeHtml(cb.Name || 'No name')}</strong><br>
        <small>📞 ${escapeHtml(cb.Phone || 'No phone')}</small><br>
        <small>🗓️ ${cbDate.toLocaleString()}</small><br>
        <small style="color: ${isPast ? 'var(--danger)' : 'var(--success)'};">${timeString}</small>
      </div>
    `}).join('');
}

function goToCallback(leadId) {
  if (isFilterActive) {
    const filteredIndex = filteredData.findIndex(f => f._id === leadId);
    if (filteredIndex !== -1) {
      currentIndex = filteredIndex;
    } else {
      // If not in filtered data, deactivate filter and go to the row
      isFilterActive = false;
      filteredData = [];
      updateFilterStats();
      updateFilteredContactsList();
      currentIndex = data.findIndex(d => d._id === leadId);
    }
  } else {
    currentIndex = data.findIndex(d => d._id === leadId);
  }
  showRow(currentIndex);
  updateCurrentPosition();
}

function toggleCallbacksPanel() {
  const rightPanel = document.getElementById('rightPanel');
  rightPanel.style.display = 'flex'; // Ensure the panel is visible

  const callbacksSection = rightPanel.querySelector('#callbacksList').parentElement;
  const filterDispositionSection = rightPanel.querySelector('.filter-section'); // This gets the first one
  const filterContactsSection = rightPanel.querySelector('#filteredContactsList').parentElement;

  const isCallbacksVisible = callbacksSection.style.display !== 'none';

  if (isCallbacksVisible && filterDispositionSection.style.display === 'none') {
    // Callbacks are visible, filters are hidden. Show filters, hide callbacks.
    callbacksSection.style.display = 'none';
    filterDispositionSection.style.display = 'block';
    filterContactsSection.style.display = 'block';
  } else {
    // Filters are visible, callbacks are hidden (or all are visible). Show callbacks, hide filters.
    callbacksSection.style.display = 'block';
    filterDispositionSection.style.display = 'none';
    filterContactsSection.style.display = 'none';
  }
}

// ==========================================
// FUNCIONES DE AGENTE
// ==========================================
// Carga de leads asignados, manejo de disposiciones y navegación.

async function loadAgentData() {
  try {
    const resp = await fetch(`${CONFIG.API_BASE_URL}/agent/data`, {
      headers: { 'Authorization': `Bearer ${userToken}` }
    });
    if (!resp.ok) {
      showToast('Error loading agent data');
      return;
    }
    const result = await resp.json();
    data = result.data;
    currentIndex = result.currentIndex || 0;
    lastSavedIndex = -1;
    isFilterActive = false;
    filteredData = [];
    selectedDispositions = [];
    availableDispositions = [];
    extractDispositionsFromData();
    updateFilterStats();
    showRow(currentIndex);
    updateCounters();
    updateCurrentPosition();
  } catch (err) {
    showToast('Connection error while loading data');
  }
}

function loadUserData() {
  const userData = JSON.parse(localStorage.getItem(`userData_${currentUser.id}`) || '{}');
  historyLog = userData.history || [];
  sessionDispositions = userData.dispositions || {};
  updateHistory();
  updateCounters();
}

function extractDispositionsFromData() {
  const set = new Set();
  data.forEach((row) => { const d = (row['DISPOSITION'] || '').toString().trim(); if (d) set.add(d); });
  availableDispositions = Array.from(set).sort();
  updateFilterOptions();
}

function updateFilterOptions() {
  const el = document.getElementById('filterOptions');
  if (!availableDispositions.length) {
    el.innerHTML = '<p style="text-align:center;color:var(--subtext);">No dispositions in data</p>';
    return;
  }
  el.innerHTML = availableDispositions.map(d => `
    <div class="filter-option">
      <input type="checkbox" id="filter-${d}" value="${d}">
      <label for="filter-${d}">${d}</label>
    </div>`).join('');
}

function toggleFilterPanel() {
  const right = document.getElementById('rightPanel');
  const callbacksList = right.querySelector('#callbacksList').parentElement;
  const filterSection = right.querySelector('.filter-section');
  const filteredContacts = right.querySelector('#filteredContactsList').parentElement;

  if (right.style.display === 'flex') {
    right.style.display = 'none';
    document.getElementById('toggleFilterBtn').textContent = '🔍 Show Filters';
  } else {
    right.style.display = 'flex';
    document.getElementById('toggleFilterBtn').textContent = '🔍 Hide Filters';
    if (data.length) extractDispositionsFromData();
    callbacksList.style.display = 'none';
    filterSection.style.display = 'block';
    filteredContacts.style.display = 'block';
  }
}

function selectAllDispositions() { document.querySelectorAll('#filterOptions input[type="checkbox"]').forEach(cb => cb.checked = true); }

function clearFilter() {
  document.querySelectorAll('#filterOptions input[type="checkbox"]').forEach(cb => cb.checked = false);
  selectedDispositions = [];
  isFilterActive = false;
  filteredData = [];
  currentIndex = 0;
  updateFilterStats();
  showRow(currentIndex);
  updateCurrentPosition();
}

function hideFilterPanel() {
  document.getElementById('rightPanel').style.display = 'none';
  document.getElementById('toggleFilterBtn').textContent = '🔍 Show Filters';
}

function applyFilter() {
  const checked = Array.from(document.querySelectorAll('#filterOptions input[type="checkbox"]:checked')).map(cb => cb.value);
  selectedDispositions = checked;
  if (!selectedDispositions.length) {
    showToast('Please select at least one disposition to filter');
    return;
  }
  filteredData = data.filter(obj => selectedDispositions.includes((obj['DISPOSITION'] || '').toString()));
  isFilterActive = true;
  currentIndex = 0;
  updateFilterStats();
  updateFilteredContactsList();
  showRow(currentIndex);
  updateCurrentPosition();
}

function updateFilterStats() {
  const stats = document.getElementById('filterStats');
  const currentData = isFilterActive ? filteredData.map(f => f.row) : data;
  stats.textContent = `Showing: ${currentData.length} of ${data.length} contacts`;
  if (isFilterActive) stats.innerHTML += `<br><small>Filter active: ${selectedDispositions.join(', ')}</small>`;
}

function updateFilteredContactsList() {
  const list = document.getElementById('filteredContactsList');
  if (!filteredData.length) {
    list.innerHTML = '<p style="text-align:center;color:var(--subtext);">No contacts match the filter</p>';
    return;
  }
  list.innerHTML = filteredData.map((row, i) => {
    const name = row['Name'] || 'No name';
    const phone = row['Phone'] || 'No phone';
    const dispo = row['DISPOSITION'] || 'No disposition';
    return `
      <div class="filter-option" style="cursor:pointer;padding:8px;margin:2px 0;border-radius:4px;border:1px solid var(--border);" onclick="goToFilteredContact(${i})">
        <strong>${escapeHtml(name)}</strong><br><small>📞 ${escapeHtml(phone)}</small><br><small>🟦 ${escapeHtml(dispo)}</small>
      </div>`;
  }).join('');
  feather.replace();
}

function goToFilteredContact(i) {
  if (!isFilterActive) return;
  currentIndex = i;
  showRow(currentIndex);
  updateCurrentPosition();
}

// Renderiza la fila actual de datos (Lead) en el contenedor principal.
// Maneja la visualización de detalles, notas, historial y acciones de disposición.
function showRow(index) {
  const container = document.getElementById('dataContainer');
  const currentData = isFilterActive ? filteredData : data;
  if (!currentData || !currentData[index]) {
    container.style.display = 'none';
    return;
  }
  const row = currentData[index];

  let dateSent = row['Date Sent'] || row['Date'] || '';
  if (typeof dateSent === 'number') {
    const excelEpoch = new Date(1899, 11, 30);
    const jsDate = new Date(excelEpoch.getTime() + dateSent * 24 * 60 * 60 * 1000);
    dateSent = jsDate.toLocaleDateString();
  }

  container.style.display = 'block';
  container.innerHTML = `
    ${isFilterActive ? '<div style="background:var(--accent);color:white;padding:8px;border-radius:6px;margin-bottom:12px;text-align:center;">🔍 Filtered View</div>' : ''}
    <div class="row-item">
      <span class="label">Date Sent:</span>
      <span>${escapeHtml(dateSent)}</span>
    </div>
    <div class="row-item">
      <span class="label">Prev. Company:</span>
      <span>${escapeHtml(row['Prev. Company'] || '')}</span>
    </div>
    <div class="row-item">
      <span class="label">Name:</span>
      <span>${escapeHtml(row['Name'] || '')}</span>
    </div>
    <div class="row-item">
      <span class="label">Address:</span>
      <span>${escapeHtml(row['Address'] || '')}</span>
    </div>
    <div class="row-item">
      <span class="label">Phone:</span>
      <span><a href="${phoneTelHref(row['Phone'] || '')}" id="phoneLink">Call: ${escapeHtml(row['Phone'] || '')}</a></span>
    </div>
    <div class="row-item">
      <span class="label">Email or Second Phone:</span>
      <span>${escapeHtml(row['Email or Second Phone'] || '')}</span>
    </div>
    <div class="row-item">
      <span class="label">Product:</span>
      <span>${escapeHtml(row['Product'] || '')}</span>
    </div>
    <div class="row-item">
      <span class="label">Prev. Status:</span>
      <span>${escapeHtml(row['Prev. Status'] || '')}</span>
    </div>
    <div class="row-item">
      <span class="label">Call Log:</span>
      <span>${escapeHtml(row['Call Log'] || '')}</span>
    </div>

    <hr>

    <div id="agent-actions">
        <div class="row-item">
          <span class="label">Disposition:</span>
          <select id="dispositionSelect">
            <option value="">Select...</option>
            <option value="NA">NA</option>
            <option value="DNC">DNC</option>
            <option value="ADP">ADP</option>
            <option value="WN">WN</option>
            <option value="VM">VM</option>
            <option value="DC">DC</option>
            <option value="ND/SD">ND/SD</option>
            <option value="FUTURE">FUTURE</option>
            <option value="KICKED">KICKED</option>
            <option value="NI">NI</option>
            <option value="HU">HU</option>
            <option value="Callback">Callback</option>
          </select>
        </div>

        <div id="callback-section" class="row-item" style="display: none;">
            <span class="label">Callback Date:</span>
            <div>
                <input type="date" id="callbackDate" class="form-input" style="margin-right: 8px; width: auto;">
                <input type="time" id="callbackTime" class="form-input" style="width: auto;">
            </div>
        </div>

        <div class="row-item">
            <span class="label">Notes:</span>
            <textarea id="notesTextarea" class="form-input" rows="4" placeholder="Write your notes here...">${escapeHtml(row.notes || '')}</textarea>
        </div>

        <div class="row-item">
          <span class="label">Timestamp:</span>
          <span id="timestamp">${escapeHtml(row['Timestamp'] || '-')}</span>
        </div>
    </div>
  `;

  const select = document.getElementById('dispositionSelect');
  select.value = (row['DISPOSITION'] || '');
  select.removeEventListener('change', handleDispositionChange);
  select.addEventListener('change', handleDispositionChange);

  // Show/hide callback section based on disposition
  const callbackSection = document.getElementById('callback-section');
  const specialDispositions = ['Callback', 'FUTURE', 'ND/SD'];

  if (specialDispositions.includes(row.DISPOSITION)) {
    callbackSection.style.display = 'grid';
    if (row.callback) {
      const [date, time] = row.callback.split('T');
      document.getElementById('callbackDate').value = date;
      document.getElementById('callbackTime').value = time.substring(0, 5);
    }
  } else {
    callbackSection.style.display = 'none';
  }

  feather.replace();
}

// Maneja el cambio en el selector de disposición.
// Muestra/oculta campos adicionales (callback) y guarda automáticamente si no es una disposición especial.
function handleDispositionChange() {
  const select = document.getElementById('dispositionSelect');
  const callbackSection = document.getElementById('callback-section');
  const disposition = select.value;
  const specialDispositions = ['Callback', 'FUTURE', 'ND/SD'];

  if (specialDispositions.includes(disposition)) {
    callbackSection.style.display = 'grid';
  } else {
    callbackSection.style.display = 'none';
  }

  saveDisposition();

  if (!specialDispositions.includes(disposition)) {
    const autoNext = document.getElementById('autoNextCheckbox');
    if (autoNext && autoNext.checked) {
      const currentData = isFilterActive ? filteredData : data;
      if (currentIndex < currentData.length - 1) setTimeout(() => nextRow(), 300);
    }
  }
}

// Guarda la disposición seleccionada, notas y callbacks.
// Actualiza el estado local, el historial, las estadísticas y sincroniza con el backend.
function saveDisposition() {
  const select = document.getElementById('dispositionSelect');
  if (!select) return;

  const currentData = isFilterActive ? filteredData : data;
  const entry = currentData[currentIndex];
  if (!entry) return;

  const originalIndex = entry._id; // Use lead's _id
  if (originalIndex === undefined) return;

  const disposition = select.value;
  const notes = document.getElementById('notesTextarea').value;
  const callbackDate = document.getElementById('callbackDate').value;
  const callbackTime = document.getElementById('callbackTime').value;

  let callback = null;
  const specialDispositions = ['Callback', 'FUTURE', 'ND/SD'];

  if (specialDispositions.includes(disposition) && callbackDate && callbackTime) {
    callback = `${callbackDate}T${callbackTime}`;
  }

  const updatedRow = {
    DISPOSITION: disposition,
    Timestamp: new Date().toISOString(),
    notes: notes,
    callback: callback
  };

  // Update local data optimisticly
  Object.assign(data.find(d => d._id === originalIndex), updatedRow);

  document.getElementById('timestamp').textContent = updatedRow.Timestamp;

  const row = data.find(d => d._id === originalIndex);
  const key = `${row.Name || 'unknown'}_${row.Phone || 'unknown'}`;
  const histEntry = { key, name: row.Name || '(No name)', address: row.Address || '(No address)', phone: row.Phone || '(No phone)', disposition, timestamp: updatedRow.Timestamp, rowNumber: currentIndex + 1, currentSession: true };

  const exIdx = historyLog.findIndex(h => h.key === key);

  if (disposition) {
    if (exIdx !== -1) {
      // Entry exists in this session
      const prevDisp = historyLog[exIdx].disposition;
      if (prevDisp !== disposition) {
        // Disposition changed, decrement old and increment new
        if (sessionDispositions[prevDisp]) sessionDispositions[prevDisp]--;
        sessionDispositions[disposition] = (sessionDispositions[disposition] || 0) + 1;
      }
      // If matches, do nothing (prevent double count)
    } else {
      // New entry for this session
      sessionDispositions[disposition] = (sessionDispositions[disposition] || 0) + 1;
    }
  }

  if (exIdx !== -1) historyLog[exIdx] = histEntry;
  else historyLog.push(histEntry);

  localStorage.setItem(`userData_${currentUser.id}`, JSON.stringify({ history: historyLog, dispositions: sessionDispositions }));

  lastSavedIndex = currentIndex;
  updateHistory();
  updateCounters();
  updateStatsOnBackend();
  saveProgressOnBackend(currentIndex, updatedRow, originalIndex);

  if (disposition && !availableDispositions.includes(disposition)) {
    availableDispositions.push(disposition);
    availableDispositions.sort();
    updateFilterOptions();
  }

  if (isFilterActive) updateFilteredContactsList();

  loadCallbacks();
}

// Sincroniza las estadísticas de sesión del agente con el backend.
async function updateStatsOnBackend() {
  try {
    await fetch(`${CONFIG.API_BASE_URL}/agent/stats`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${userToken}`
      },
      body: JSON.stringify({ stats: sessionDispositions })
    });
  } catch (err) {
    console.error('Error updating stats on backend:', err);
  }
}

// Guarda el progreso del agente (índice y datos del lead) en el backend.
async function saveProgressOnBackend(currentIndex, updatedRow, originalIndex) {
  try {
    await fetch(`${CONFIG.API_BASE_URL}/agent/progress`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${userToken}`
      },
      body: JSON.stringify({ currentIndex, updatedRow, originalIndex })
    });
  } catch (err) {
    console.error('Error saving progress on backend:', err);
  }
}

// Navega al siguiente lead en la lista.
// Guarda la disposición actual antes de avanzar y maneja la llamada automática si está activada.
function nextRow() {
  saveDisposition();
  const currentData = isFilterActive ? filteredData : data;
  if (currentIndex < currentData.length - 1) {
    currentIndex++;
    showRow(currentIndex);
    updateCurrentPosition();
    const autoCall = document.getElementById('autoCallCheckbox');
    if (autoCall && autoCall.checked) {
      setTimeout(() => {
        const link = document.getElementById('phoneLink');
        if (link) link.click();
      }, 500);
    }
  } else {
    showToast('End of list.');
  }
}

function prevRow() {
  saveDisposition();
  if (currentIndex > 0) {
    currentIndex--;
    showRow(currentIndex);
    updateCurrentPosition();
  } else {
    showToast('You are at the first row.');
  }
}

function goToRow() {
  const val = parseInt(document.getElementById('rowInput').value);
  const currentData = isFilterActive ? filteredData : data;
  if (isNaN(val) || val < 1 || val > currentData.length) {
    showToast(`Please enter a valid number between 1 and ${currentData.length}`);
    return;
  }
  saveDisposition();
  currentIndex = val - 1;
  showRow(currentIndex);
  updateCurrentPosition();
}

function updateCurrentPosition() {
  const el = document.getElementById('currentPosition');
  if (!el) return;
  const currentData = isFilterActive ? filteredData : data;
  el.textContent = `Contact ${currentIndex + 1} of ${currentData.length}`;
}

// Renderiza el historial de acciones recientes en el panel izquierdo.
function updateHistory() {
  const h = document.getElementById('history');
  if (!h) return;
  if (!historyLog.length) {
    h.innerHTML = 'No records yet.';
    return;
  }
  const sorted = [...historyLog].reverse();
  h.innerHTML = sorted.map(hc => `
    <div class="history-entry" style="${hc.currentSession ? 'border-left:3px solid var(--accent);padding-left:8px;background:rgba(59,130,246,0.06);' : ''}">
      <strong>${escapeHtml(hc.name)}</strong><br>${escapeHtml(hc.address)}<br>📞 ${escapeHtml(hc.phone)}<br>🟦 ${escapeHtml(hc.disposition)} <small>(${escapeHtml(hc.timestamp)})</small>${hc.rowNumber ? `<br><small style="color:var(--accent);">Row: ${hc.rowNumber}</small>` : ''}${hc.currentSession ? `<br><small style="color:var(--accent);">✓ Current session</small>` : ''}
    </div>`).join('');
  feather.replace();
}

// Actualiza los contadores de la sesión (Total, No Contestan, Porcentajes).
function updateCounters() {
  const c = document.getElementById('counters');
  if (!c) return;
  const noAnswerDispositions = ['NA', 'VM', 'DC'];
  let totalNoAnswer = 0;
  noAnswerDispositions.forEach(d => { if (sessionDispositions[d]) totalNoAnswer += sessionDispositions[d]; });
  const totalSession = Object.values(sessionDispositions).reduce((s, v) => s + (v || 0), 0);
  const noAnswerPercentage = totalSession > 0 ? ((totalNoAnswer / totalSession) * 100).toFixed(1) : 0;
  c.innerHTML = ''; // Clear previous content
  c.innerHTML = `
    <div class="percentage-container">
      <div class="counter-row">
        <span class="counter-label">No answer (NA, VM, DC):</span>
        <span class="counter-value">${noAnswerPercentage}%</span>
      </div>
      <div class="counter-row">
        <span class="counter-label">Total in session:</span>
        <span class="counter-value">${totalSession}</span>
      </div>
      <div class="counter-row">
        <span class="counter-label">No answer:</span>
        <span class="counter-value">${totalNoAnswer}</span>
      </div>
    </div>`;
}



// Carga y renderiza la lista de Callbacks pendientes para el agente.
async function loadCallbacks() {
  try {
    const resp = await fetch(`${CONFIG.API_BASE_URL}/agent/callbacks`, {
      headers: { 'Authorization': `Bearer ${userToken}` }
    });
    if (!resp.ok) {
      console.error('Error loading callbacks');
      return;
    }
    const callbacks = await resp.json();
    const list = document.getElementById('callbacksList');
    if (!list) return;

    if (!callbacks.length) {
      list.innerHTML = '<p style="text-align:center;color:var(--subtext);">No pending callbacks.</p>';
      return;
    }

    list.innerHTML = callbacks.map(cb => `
      <div class="history-entry" style="border-left: 3px solid var(--warning);">
        <div style="display:flex;justify-content:space-between;">
          <strong>${escapeHtml(cb.Name)}</strong>
          <small>${new Date(cb.callback).toLocaleString()}</small>
        </div>
        <div style="margin-top:4px;">📞 <a href="${phoneTelHref(cb.Phone)}">${escapeHtml(cb.Phone)}</a></div>
        ${cb.notes ? `<div style="margin-top:4px;font-style:italic;color:var(--subtext);">${escapeHtml(cb.notes)}</div>` : ''}
      </div>
    `).join('');
    feather.replace();

  } catch (err) {
    console.error('Error loading callbacks:', err);
  }
}

async function exportCallbacks() {
  try {
    const resp = await fetch(`${CONFIG.API_BASE_URL}/agent/callbacks`, {
      headers: { 'Authorization': `Bearer ${userToken}` }
    });
    if (!resp.ok) {
      showToast('Error exporting callbacks.');
      return;
    }
    const callbacks = await resp.json();

    if (!callbacks.length) {
      showToast('No callbacks to export.');
      return;
    }

    const dataToExport = callbacks.map(cb => ({
      Name: cb.Name || '',
      Phone: cb.Phone || '',
      Callback: cb.callback ? new Date(cb.callback).toLocaleString() : '',
      Notes: cb.notes || ''
    }));

    const worksheet = XLSX.utils.json_to_sheet(dataToExport);
    const workbook = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(workbook, worksheet, "Callbacks");

    const fecha = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
    const filename = `callbacks_${fecha}.xlsx`;
    XLSX.writeFile(workbook, filename);

  } catch (err) {
    console.error('Error exporting callbacks:', err);
    showToast('Connection error while exporting callbacks.');
  }
}

// Genera y descarga un archivo de texto con el resumen de disposiciones de la sesión actual.
function exportSummaryTXT() {
  let text = isFilterActive ? 'DISPOSITION Summary (Filtered Contacts)\n\n' : 'DISPOSITION Summary (Current Session)\n\n';
  if (!Object.keys(sessionDispositions).length) {
    text += 'No dispositions recorded in this session.\n';
  } else {
    for (const [k, v] of Object.entries(sessionDispositions)) text += `${k}: ${v}\n`;
    const noAnswerDispositions = ['NA', 'VM', 'DC'];
    let totalNoAnswer = 0;
    noAnswerDispositions.forEach(d => { if (sessionDispositions[d]) totalNoAnswer += sessionDispositions[d]; });
    const totalSession = Object.values(sessionDispositions).reduce((s, v) => s + (v || 0), 0);
    const noAnswerPercentage = totalSession > 0 ? ((totalNoAnswer / totalSession) * 100).toFixed(1) : 0;
    text += `\nNo answer (NA, VM, DC): ${totalNoAnswer} (${noAnswerPercentage}%)`;
    const nonContacts = ['NA', 'VM', 'DC'];
    let totalContacts = 0;
    Object.keys(sessionDispositions).forEach(d => { if (!nonContacts.includes(d)) totalContacts += sessionDispositions[d]; });
    text += `
Contacts: ${totalContacts}`;
    if (isFilterActive) {
      text += `

--- FILTER APPLIED ---
Selected dispositions: ${selectedDispositions.join(', ')}
Contacts shown: ${filteredData.length} of ${data.length}`;
    }
  }

  const contentEl = document.getElementById('exportSummaryContent');
  contentEl.textContent = text;
  document.getElementById('exportSummaryModal').style.display = 'flex';
}

function clearHistory() {
  if (!confirm('Are you sure you want to clear the history?')) return;
  historyLog = [];
  const userData = JSON.parse(localStorage.getItem(`userData_${currentUser.id}`) || '{}');
  userData.history = [];
  localStorage.setItem(`userData_${currentUser.id}`, JSON.stringify(userData));
  updateHistory();
}

function clearDispositionData() {
  if (!confirm('Are you sure you want to delete all saved disposition data?')) return;
  sessionDispositions = {};
  const userData = JSON.parse(localStorage.getItem(`userData_${currentUser.id}`) || '{}');
  userData.dispositions = {};
  localStorage.setItem(`userData_${currentUser.id}`, JSON.stringify(userData));
  updateCounters();
  showToast('Disposition data cleared successfully.');
}

function logout() {
  currentUser = null;
  userToken = null;
  localStorage.removeItem('userToken');
  localStorage.removeItem('currentUser');
  showScreen('loginScreen');
  document.getElementById('username').value = '';
  document.getElementById('password').value = '';
  document.getElementById('loginError').style.display = 'none';
}

// ==========================================
// LOGIN Y GESTIÓN DE SESIÓN
// ==========================================

function setupEventListeners() {
  document.getElementById('loginBtn').addEventListener('click', handleLogin);
  document.getElementById('password').addEventListener('keypress', (e) => { if (e.key === 'Enter') handleLogin(); });
}

// Maneja el proceso de inicio de sesión.
// Valida credenciales con el backend, guarda el token y redirige a la pantalla correspondiente según el rol.
async function handleLogin() {
  const username = document.getElementById('username').value.trim();
  const password = document.getElementById('password').value;
  const loginError = document.getElementById('loginError');

  if (!username || !password) {
    loginError.textContent = 'Please fill all fields';
    loginError.style.display = 'block';
    return;
  }

  const result = await login(username, password);
  if (result.success) {
    currentUser = result.user;
    userToken = result.token;
    localStorage.setItem('userToken', userToken);
    localStorage.setItem('currentUser', JSON.stringify(currentUser));
    loginError.style.display = 'none';
    if (currentUser.role === 'admin') {
      showScreen('adminScreen');
      initializeAdminHub();
    } else {
      showScreen('appScreen');
      initializeApp();
    }
  } else {
    loginError.textContent = result.error || 'Invalid credentials';
    loginError.style.display = 'block';
  }
}

async function login(username, password) {
  try {
    const resp = await fetch(`${CONFIG.API_BASE_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    const payload = await resp.json();
    if (!resp.ok) {
      return { success: false, error: payload.error || 'Invalid credentials' };
    }
    return { success: true, ...payload };
  } catch (err) {
    return { success: false, error: 'Connection error' };
  }
}

function checkExistingSession() {
  const savedToken = localStorage.getItem('userToken');
  const savedUser = localStorage.getItem('currentUser');
  if (savedToken && savedUser) {
    currentUser = JSON.parse(savedUser);
    userToken = savedToken;
    if (currentUser.role === 'admin') {
      showScreen('adminScreen');
      initializeAdminHub();
    } else {
      showScreen('appScreen');
      initializeApp();
    }
  } else {
    showScreen('loginScreen');
  }
}

// ===== HELPERS =====
window.goToFilteredContact = function (i) { goToFilteredContactInline(i); };
function goToFilteredContactInline(i) { goToFilteredContact(i); }

// Realiza una búsqueda en tiempo real sobre los datos cargados localmente (para el Agente).
// Filtra por cualquier campo que coincida con el término de búsqueda.
function performSearch(searchTerm) {
  const lowerCaseSearchTerm = searchTerm.toLowerCase();
  if (!lowerCaseSearchTerm) {
    isFilterActive = false;
    filteredData = [];
    showRow(currentIndex);
    updateCurrentPosition();
    updateFilterStats();
    return;
  }

  isFilterActive = true;
  filteredData = data.filter((row) => {
    return Object.values(row).some(val =>
      String(val).toLowerCase().includes(lowerCaseSearchTerm)
    );
  });

  currentIndex = 0;
  showRow(currentIndex);
  updateCurrentPosition();
  updateFilterStats();
  updateFilteredContactsList();
}



// ===== INITIALIZATION ======
document.addEventListener('DOMContentLoaded', () => {
  setupEventListeners();
  checkExistingSession();
});

async function showHistory(leadId) {
  try {
    const resp = await fetch(`${CONFIG.API_BASE_URL}/agent/leads/${leadId}/history`, {
      headers: { 'Authorization': `Bearer ${userToken}` }
    });

    if (!resp.ok) {
      showToast('Error fetching history');
      return;
    }

    const history = await resp.json();
    const list = document.getElementById('leadHistoryList');

    if (!history.length) {
      list.innerHTML = '<p style="text-align:center;color:var(--subtext);">No history available</p>';
    } else {
      list.innerHTML = history.map(h => `
        <div class="history-entry">
          <strong>${escapeHtml(h.action)}</strong>
          <div style="font-size:0.9em;margin-top:4px;">Disposition: ${escapeHtml(h.disposition || 'N/A')}</div>
          ${h.note ? `<div style="font-size:0.9em;margin-top:4px;color:var(--text);">Note: ${escapeHtml(h.note)}</div>` : ''}
          <small style="display:block;margin-top:8px;">${new Date(h.timestamp).toLocaleString()}</small>
        </div>
      `).join('');
    }

    document.getElementById('leadHistoryModal').style.display = 'flex';
    feather.replace();

    // Logic to handle the new Form Modal
    function openLeadForm() {
      const modal = document.getElementById('leadFormModal');
      const currentLead = isFilterActive ? filteredData[currentIndex] : data[currentIndex];

      if (!currentLead) {
        showToast('No lead selected');
        return;
      }

      // Pre-fill fields
      document.getElementById('formFullName').value = currentLead.Name || '';
      document.getElementById('formPhone').value = currentLead.Phone || '';
      document.getElementById('formAddress').value = currentLead.Address || '';

      // Clear other fields or set defaults
      document.getElementById('formAgentCode').value = '';
      document.getElementById('formConfBy').value = '';
      document.getElementById('formMasterNotes').value = '';
      document.getElementById('formCrmNotes').value = '';
      document.getElementById('formVaTag').value = '';
      document.getElementById('formApptDate').value = '';

      // Reset Products
      const container = document.getElementById('formProductsContainer');
      container.innerHTML = '';
      addProductRow(); // Add initial row

      modal.style.display = 'flex';
    }

    function addProductRow() {
      const container = document.getElementById('formProductsContainer');
      const row = document.createElement('div');
      row.className = 'product-row';
      row.style.display = 'flex';
      row.style.gap = '8px';
      row.style.marginTop = '8px';

      row.innerHTML = `
    <select class="form-input product-select" style="flex: 2;">
      <option value="Roof">Roof</option>
      <option value="Windows">Windows</option>
      <option value="Doors">Doors</option>
      <option value="Kitchen">Kitchen</option>
      <option value="Bathroom">Bathroom</option>
    </select>
    <select class="form-input quantity-select" style="flex: 1;">
      <option value="1">1</option>
      <option value="2">2</option>
      <option value="3">3</option>
      <option value="4">4</option>
      <option value="5+">5+</option>
    </select>
    <button class="small-btn danger-btn remove-product-btn" style="width: auto; padding: 0 8px;"><i data-feather="trash-2"></i></button>
  `;

      // Add remove event
      row.querySelector('.remove-product-btn').addEventListener('click', () => {
        if (container.children.length > 1) {
          container.removeChild(row);
        } else {
          showToast('At least one product is required');
        }
      });

      container.appendChild(row);
      feather.replace();
    }

    function copyFormToClipboard() {
      const company = document.getElementById('formCompany').value;
      const team = document.getElementById('formTeam').value;
      const agentCode = document.getElementById('formAgentCode').value;
      const fullName = document.getElementById('formFullName').value;
      const phone = document.getElementById('formPhone').value;
      const language = document.getElementById('formLanguage').value;
      const maritalStatus = document.getElementById('formMaritalStatus').value;
      const address = document.getElementById('formAddress').value;

      // Products
      const productRows = document.querySelectorAll('.product-row');
      let products = [];
      productRows.forEach(row => {
        const prod = row.querySelector('.product-select').value;
        const qty = row.querySelector('.quantity-select').value;
        products.push(`${prod} (${qty})`);
      });
      const productStr = products.join(', ');

      const apptDate = document.getElementById('formApptDate').value;
      const apptAmPm = document.getElementById('formApptAmPm').value;
      const confBy = document.getElementById('formConfBy').value;
      const masterNotes = document.getElementById('formMasterNotes').value;
      const crmNotes = document.getElementById('formCrmNotes').value;
      const vaTag = document.getElementById('formVaTag').value;
      const leadQuality = document.getElementById('formLeadQuality').value;
      const source = document.getElementById('formSource').value;
      const leadStatus = document.getElementById('formLeadStatus').value;

      const text = `
Company: ${company}
Team: ${team}
Agent Code: ${agentCode}
Full Name: ${fullName}
Phone Number: ${phone}
Language: ${language}
Marital Status: ${maritalStatus}
Address: ${address}
Product: ${productStr}
Appt. Date & Time: ${apptDate}${apptAmPm}
Conf. by: ${confBy}
Master Notes: ${masterNotes}
CRM Notes: ${crmNotes}
VA Tag: ${vaTag}
Lead Quality: ${leadQuality}
Source: ${source}
Lead Status: ${leadStatus}
`.trim();

      navigator.clipboard.writeText(text).then(() => {
        showToast('Form data copied to clipboard', 'success');
      }).catch(err => {
        console.error('Copy error:', err);
        showToast('Failed to copy', 'error');
      });
    }
    document.getElementById('closeHistoryModalBtn').onclick = () => {
      document.getElementById('leadHistoryModal').style.display = 'none';
    };

  } catch (err) {
    console.error('Error showing history:', err);
    showToast('Connection error');
  }
}

// Logic to handle the new Form Modal
function openLeadForm() {
  const modal = document.getElementById('leadFormModal');
  const currentLead = isFilterActive ? filteredData[currentIndex] : data[currentIndex];

  if (!currentLead) {
    showToast('No lead selected');
    return;
  }

  // Pre-fill fields
  document.getElementById('formFullName').value = currentLead.Name || '';
  document.getElementById('formPhone').value = currentLead.Phone || '';
  document.getElementById('formAddress').value = currentLead.Address || '';

  // Clear other fields or set defaults
  document.getElementById('formAgentCode').value = '';
  document.getElementById('formConfBy').value = '';
  document.getElementById('formMasterNotes').value = '';
  document.getElementById('formCrmNotes').value = '';
  document.getElementById('formVaTag').value = '';
  document.getElementById('formApptMonth').value = '';
  document.getElementById('formApptDay').value = '';
  document.getElementById('formApptHour').value = '';

  // Reset Products
  const container = document.getElementById('formProductsContainer');
  container.innerHTML = '';
  addProductRow(); // Add initial row

  modal.style.display = 'flex';
}

function addProductRow() {
  const container = document.getElementById('formProductsContainer');
  const row = document.createElement('div');
  row.className = 'product-row';
  row.style.display = 'flex';
  row.style.gap = '8px';
  row.style.marginTop = '8px';

  let qtyOptions = '';
  for (let i = 1; i <= 15; i++) {
    qtyOptions += `<option value="${i}">${i}</option>`;
  }
  qtyOptions += `<option value="Custom">Custom</option>`;

  row.innerHTML = `
    <select class="form-input product-select" style="flex: 2;">
      <option value="Roof">Roof</option>
      <option value="Windows">Windows</option>
      <option value="Doors">Doors</option>
      <option value="Kitchen">Kitchen</option>
      <option value="Bathroom">Bathroom</option>
    </select>
    <div class="qty-wrapper" style="flex: 1; display: none;">
      <select class="form-input quantity-select" style="width: 100%;">
        ${qtyOptions}
      </select>
      <input type="text" class="form-input quantity-custom" style="display: none; width: 100%;" placeholder="#">
    </div>
    <button class="small-btn danger-btn remove-product-btn" style="width: auto; padding: 0 8px;"><i data-feather="trash-2"></i></button>
  `;

  const productSelect = row.querySelector('.product-select');
  const qtyWrapper = row.querySelector('.qty-wrapper');
  const qtySelect = row.querySelector('.quantity-select');
  const qtyCustom = row.querySelector('.quantity-custom');

  // Logic: Show/Hide Qty based on Product
  function updateQtyVisibility() {
    if (productSelect.value === 'Roof') {
      qtyWrapper.style.display = 'none';
      productSelect.style.flex = '3'; // Expand to fill space
    } else {
      qtyWrapper.style.display = 'block';
      productSelect.style.flex = '2';
    }
  }

  // Logic: Handle Custom Qty
  qtySelect.addEventListener('change', () => {
    if (qtySelect.value === 'Custom') {
      qtySelect.style.display = 'none';
      qtyCustom.style.display = 'block';
      qtyCustom.focus();
    }
  });

  productSelect.addEventListener('change', updateQtyVisibility);

  // Add remove event
  row.querySelector('.remove-product-btn').addEventListener('click', () => {
    if (container.children.length > 1) {
      container.removeChild(row);
    } else {
      showToast('At least one product is required');
    }
  });

  container.appendChild(row);

  // Initialize state
  updateQtyVisibility();

  feather.replace();
}

function copyFormToClipboard() {
  const company = document.getElementById('formCompany').value;
  const team = document.getElementById('formTeam').value;
  const agentCode = document.getElementById('formAgentCode').value;
  const fullName = document.getElementById('formFullName').value;
  const phone = document.getElementById('formPhone').value;
  const language = document.getElementById('formLanguage').value;
  const maritalStatus = document.getElementById('formMaritalStatus').value;
  const address = document.getElementById('formAddress').value;

  // Products
  const productRows = document.querySelectorAll('.product-row');
  let products = [];
  productRows.forEach(row => {
    const prod = row.querySelector('.product-select').value;

    if (prod === 'Roof') {
      products.push(prod);
    } else {
      const qtySelect = row.querySelector('.quantity-select');
      const qtyCustom = row.querySelector('.quantity-custom');

      let qty = qtySelect.value;
      if (qty === 'Custom' || qtySelect.style.display === 'none') {
        qty = qtyCustom.value || '?';
      }

      products.push(`${prod} (${qty})`);
    }
  });
  const productStr = products.join(', ');

  const apptMonth = document.getElementById('formApptMonth').value;
  const apptDay = document.getElementById('formApptDay').value;
  const apptHour = document.getElementById('formApptHour').value;
  const apptAmPm = document.getElementById('formApptAmPm').value;

  const apptStr = (apptMonth && apptDay && apptHour) ? `${apptMonth}/${apptDay}@${apptHour}${apptAmPm}` : '';

  const confBy = document.getElementById('formConfBy').value;
  const masterNotes = document.getElementById('formMasterNotes').value;
  const crmNotes = document.getElementById('formCrmNotes').value;
  const vaTag = document.getElementById('formVaTag').value;
  const leadQuality = document.getElementById('formLeadQuality').value;
  const source = document.getElementById('formSource').value;
  const leadStatus = document.getElementById('formLeadStatus').value;

  const text = `
Company: ${company}
Team: ${team}
Agent Code: ${agentCode}
Full Name: ${fullName}
Phone Number: ${phone}
Language: ${language}
Marital Status: ${maritalStatus}
Address: ${address}
Product: ${productStr}
Appt. Date & Time: ${apptStr}
Conf. by: ${confBy}
Master Notes: ${masterNotes}
CRM Notes: ${crmNotes}
VA Tag: ${vaTag}
Lead Quality: ${leadQuality}
Source: ${source}
Lead Status: ${leadStatus}
`.trim();

  navigator.clipboard.writeText(text).then(() => {
    showToast('Form data copied to clipboard', 'success');
  }).catch(err => {
    console.error('Copy error:', err);
    showToast('Failed to copy', 'error');
  });
}
