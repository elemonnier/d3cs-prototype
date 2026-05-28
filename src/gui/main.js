const state = {
  me: null,
  presets: null,
  arl: null,
  network: null,
  revocationQueue: [],
  activeRevocationPromptId: null,
  revocationDecisionPending: false,
  revocationRequestPending: false,
  currentView: null,
};

// permet de "réveiller" l'alerte HTML, soit en succès ou en failure (bandeau de couleur =/= alerte Chrome)
function setAlert(kind, text) {
  const el = document.getElementById('alert');
  if (!text) {
    el.innerHTML = '';
    return;
  }
  const className = kind === 'success' ? 'alert alert-success' : 'alert alert-danger';
  el.innerHTML = `<div class="${className}" role="alert">${escapeHtml(text)}</div>`;
}

// permet d'empêcher que le texte soit compris comme du html
function escapeHtml(str) {
  return String(str)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

// permet de faire une requête GET vers le backend
async function apiGet(path) {
  const r = await fetch(path, { method: 'GET', cache: 'no-store' });
  return await r.json();
}

// permet de faire une requête POST vers le backend
async function apiPost(path, payload) {
  const r = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  return await r.json();
}

// empêche l'utilisateur d'avoir accès au panel Labelling s'il n'a pas accès 
function canUseLabelling() {
  if (!state.me) return false;
  return state.me.is_authority_user || state.me.has_abs_key;
}

function hasDelegatedAccessReady() {
  if (!state.me || !state.network) return false;
  if (state.me.is_authority_user || state.me.is_authority) return false;
  return !!state.network.has_public_params
    && !!state.network.has_user_secret_key
    && !!state.network.has_tm_delegate_key
    && !state.me.has_abs_key;
}

function canUseDocuments() {
  if (!state.me) return false;
  if (state.me.is_authority_user || state.me.is_authority) return true;
  if (state.me.mode !== 'network') return true;
  if (!state.network || !state.network.enabled) return false;
  return !!state.network.has_public_params
    && !!state.network.has_user_secret_key
    && !!state.network.has_tm_delegate_key;
}

function hasAbeKeysReady() {
  if (!state.me) return false;
  if (state.me.mode !== 'network') return true;
  if (!state.network || !state.network.enabled) return false;
  return !!state.network.has_public_params
    && !!state.network.has_user_secret_key
    && !!state.network.has_tm_delegate_key;
}

function canUseRevocation() {
  if (!state.me || state.me.is_authority) return false;
  if (state.me.is_authority_user) return true;
  return !!state.me.has_abs_key && hasAbeKeysReady();
}

function shouldShowLabellingNav() {
  if (!state.me) return false;
  if (state.me.is_authority || state.me.is_authority_user) return true;
  return canUseLabelling();
}

function renderAuthedHome() {
  if (!state.me) {
    renderDefaultAuthView();
    return;
  }
  if (canUseLabelling()) {
    renderLabelling();
    return;
  }
  renderConnectedPanel();
}

function keyReceptionStatusHtml() {
  if (!state.me || !state.network || !state.network.enabled || state.me.is_authority) return '';

  const rows = [
    ['PP received', !!state.network.has_public_params],
    ['PSKS received', !!state.network.has_user_secret_key],
    ['PSKA/TM key received', !!state.network.has_tm_delegate_key],
  ];

  return `
    <div class="mt-3">
      <div><strong>Key material</strong></div>
      ${rows.map(([label, ok]) => `<div>${escapeHtml(label)}: ${ok ? 'Yes' : 'No'}</div>`).join('')}
    </div>
  `;
}

function populateConnectedDocumentsSummary() {
  const container = document.getElementById('connected-documents-summary');
  if (!container || !state.me || !canUseDocuments()) return;

  container.innerHTML = '<div class="text-muted">Checking accessible documents...</div>';
  apiGet('/api/documents').then((j) => {
    const current = document.getElementById('connected-documents-summary');
    if (!current || state.currentView !== 'connected') return;

    if (!j.ok) {
      current.innerHTML = '<div class="text-danger">Could not load accessible documents.</div>';
      return;
    }

    const docs = (j.data && j.data.documents) ? j.data.documents : [];
    const viewableDocs = docs.filter((doc) => documentStatus(doc) === 'viewable');
    if (!viewableDocs.length) {
      current.innerHTML = `
        <div class="mt-3 text-muted">
          Document access is ready, but no compatible document is currently available.
        </div>
      `;
      return;
    }

    const preview = viewableDocs
      .slice(0, 5)
      .map((doc) => `<div>#${doc.id} (${escapeHtml(doc.label.classification)}, ${escapeHtml(doc.label.mission)})</div>`)
      .join('');

    current.innerHTML = `
      <div class="mt-3">
        <div><strong>Accessible documents now</strong>: ${viewableDocs.length}</div>
        <div class="text-muted">You can already consult these ciphertexts:</div>
        <div class="mt-2">${preview}</div>
      </div>
    `;
  }).catch(() => {
    const current = document.getElementById('connected-documents-summary');
    if (!current || state.currentView !== 'connected') return;
    current.innerHTML = '<div class="text-danger">Could not load accessible documents.</div>';
  });
}

// en local, on affiche sign in / en réseau, on affiche sign up
function shouldDefaultToSignup() {
  if (!state.network || !state.network.enabled) return false;
  const nodeId = state.network.node_id || '';
  return /^U[1-9]$/i.test(nodeId);
}

// fonction de render de sign in/up
function renderDefaultAuthView() {
  if (shouldDefaultToSignup()) {
    renderSignUp();
  } else {
    renderSignIn();
  }
}

// permet de setup les credentials
function defaultSigninCredentials() {
  if (!state.network || !state.network.enabled) return { login: '', password: '' };
  const m = /^U([1-9])$/i.exec(state.network.node_id || '');
  if (!m) return { login: '', password: '' };
  const u = `u${m[1]}`;
  return { login: u, password: u };
}

function defaultSignupClearance() {
  const fallback = { classification: 'FR-DR', mission: 'M1' };
  if (!state.network || !state.network.enabled) return fallback;

  const mapping = {
    U1: { classification: 'FR-DR', mission: 'M1' },
    U2: { classification: 'FR-S', mission: 'M1' },
    U3: { classification: 'FR-DR', mission: 'M2' },
    U4: { classification: 'FR-S', mission: 'M2' },
    U5: { classification: 'FR-DR', mission: 'M1' },
    U6: { classification: 'FR-S', mission: 'M1' },
    U7: { classification: 'FR-DR', mission: 'M2' },
    U8: { classification: 'FR-S', mission: 'M2' },
    U9: { classification: 'FR-DR', mission: 'M1' },
  };

  const nodeId = String(state.network.node_id || '').toUpperCase();
  return mapping[nodeId] || fallback;
}

// affiche le nom utilisateur/autorité
function displayUserName() {
  if (!state.me) return '';
  if (state.me.is_authority) return 'authority';
  return state.me.login;
}

// affiche le navigateur
function setNav() {
  const navRight = document.getElementById('nav-right');
  navRight.innerHTML = '';

  const isAuthed = !!state.me;
  const isAuthorityUser = isAuthed && state.me.is_authority_user;
  const isAuthority = isAuthed && state.me.is_authority;

  document.getElementById('nav-labelling').parentElement.style.display = shouldShowLabellingNav() ? '' : 'none';
  document.getElementById('nav-documents').parentElement.style.display = canUseDocuments() ? '' : 'none';
  document.getElementById('nav-revocation').parentElement.style.display = canUseRevocation() ? '' : 'none';
  document.getElementById('nav-presets').parentElement.style.display = isAuthorityUser ? '' : 'none';
  document.getElementById('nav-arl').parentElement.style.display = (isAuthed && isAuthority) ? '' : 'none';

  if (!isAuthed) {
    const li1 = document.createElement('li');
    li1.className = 'nav-item';
    li1.innerHTML = `<a class="nav-link" href="#" id="nav-signin">Sign in</a>`;
    navRight.appendChild(li1);

    const li2 = document.createElement('li');
    li2.className = 'nav-item';
    li2.innerHTML = `<a class="nav-link" href="#" id="nav-signup">Sign up</a>`;
    navRight.appendChild(li2);

    document.getElementById('nav-signin').onclick = () => renderSignIn();
    document.getElementById('nav-signup').onclick = () => renderSignUp();
    return;
  }

  const liUser = document.createElement('li');
  liUser.className = 'nav-item d-flex align-items-center';
  liUser.innerHTML = state.me.is_authority
    ? `<span class="navbar-text text-white me-3">Authority</span>`
    : `<span class="navbar-text text-white me-3">${escapeHtml(state.me.login)} (${escapeHtml(state.me.clearance.classification)}, ${escapeHtml(state.me.clearance.mission)})</span>`;
  navRight.appendChild(liUser);

  const liLogout = document.createElement('li');
  liLogout.className = 'nav-item';
  liLogout.innerHTML = `<a class="nav-link" href="#" id="nav-logout">Log out</a>`;
  navRight.appendChild(liLogout);

  document.getElementById('nav-logout').onclick = async () => {
    setAlert(null, null);
    await apiPost('/api/logout', {});
    await refreshMe();
    await refreshNetworkStatus();
    renderDefaultAuthView();
  };
}

// permet de renvoyer qui est l'utilisateur connecté côté serveur
async function refreshMe() {
  const j = await apiGet('/api/me');
  state.me = j.data ? j.data : null;
  setNav();
}

// mise à jour des presets
async function refreshPresets() {
  if (!state.me) {
    state.presets = null;
    return;
  }
  const j = await apiGet('/api/presets');
  state.presets = j.data ? j.data : null;
}

// permet de recharger la liste de révocation depuis le backend
async function refreshArl() {
  if (!state.me || !state.me.is_authority_user) {
    state.arl = null;
    return;
  }
  const j = await apiGet('/api/revocations');
  state.arl = j.data ? j.data : null;
}

// recharge la liste des demandes de révocation en attente
async function refreshRevocationQueue() {
  if (!state.me || !state.me.is_authority_user) {
    state.revocationQueue = [];
    state.activeRevocationPromptId = null;
    hideRevocationRequestModal();
    return;
  }
  const j = await apiGet('/api/revocation/requests');
  state.revocationQueue = (j.ok && j.data && j.data.requests) ? j.data.requests : [];
  const liveIds = new Set(state.revocationQueue.map((x) => x.id));
  if (state.activeRevocationPromptId && !liveIds.has(state.activeRevocationPromptId)) {
    state.activeRevocationPromptId = null;
  }
}

function ensureRevocationRequestModal() {
  let modal = document.getElementById('revocation-request-modal');
  if (modal) return modal;

  modal = document.createElement('div');
  modal.className = 'modal fade';
  modal.id = 'revocation-request-modal';
  modal.tabIndex = -1;
  modal.setAttribute('aria-labelledby', 'revocation-request-modal-title');
  modal.setAttribute('aria-hidden', 'true');
  modal.setAttribute('data-bs-backdrop', 'static');
  modal.setAttribute('data-bs-keyboard', 'false');
  modal.innerHTML = `
    <div class="modal-dialog modal-dialog-centered">
      <div class="modal-content">
        <div class="modal-header">
          <h5 class="modal-title" id="revocation-request-modal-title">Pending Revocation Request</h5>
        </div>
        <div class="modal-body" id="revocation-request-modal-body"></div>
        <div class="modal-footer">
          <button type="button" class="btn btn-outline-danger" id="revocation-request-reject">Reject</button>
          <button type="button" class="btn btn-success" id="revocation-request-approve">Accept</button>
        </div>
      </div>
    </div>
  `;
  document.body.appendChild(modal);

  document.getElementById('revocation-request-reject').onclick = () => submitRevocationDecision(false);
  document.getElementById('revocation-request-approve').onclick = () => submitRevocationDecision(true);
  return modal;
}

function hideRevocationRequestModal() {
  const modal = document.getElementById('revocation-request-modal');
  if (!modal || !window.bootstrap) return;
  const instance = bootstrap.Modal.getInstance(modal);
  if (instance) instance.hide();
}

function syncRevocationRequestModal() {
  if (!state.me || !state.me.is_authority_user || state.revocationQueue.length === 0) {
    state.activeRevocationPromptId = null;
    hideRevocationRequestModal();
    return;
  }

  const current = state.revocationQueue.find((req) => req.id === state.activeRevocationPromptId)
    || state.revocationQueue[0];
  state.activeRevocationPromptId = current.id;

  const modal = ensureRevocationRequestModal();
  document.getElementById('revocation-request-modal-body').innerHTML = `
    <div class="mb-2"><strong>Request</strong>: #${current.id}</div>
    <div class="mb-2"><strong>User</strong>: ${escapeHtml(current.requester)}</div>
    <div><strong>Missions</strong>: ${current.missions.map((m) => escapeHtml(m)).join(', ')}</div>
  `;
  document.getElementById('revocation-request-reject').disabled = state.revocationDecisionPending;
  document.getElementById('revocation-request-approve').disabled = state.revocationDecisionPending;

  if (window.bootstrap) {
    bootstrap.Modal.getOrCreateInstance(modal).show();
  }
}

async function submitRevocationDecision(approve) {
  if (state.revocationDecisionPending || !state.activeRevocationPromptId) return;
  state.revocationDecisionPending = true;
  syncRevocationRequestModal();

  try {
    const id = state.activeRevocationPromptId;
    const r = await apiPost('/api/revocation/approve', { id, approve });
    if (!r.ok) {
      setAlert('error', r.message || 'Revocation update failed');
      return;
    }

    setAlert('success', r.message || (approve ? 'Revocation approved' : 'Revocation rejected'));
    state.activeRevocationPromptId = null;
    hideRevocationRequestModal();
    await refreshRevocationQueue();
    if (state.currentView === 'revocation' && state.me && state.me.is_authority_user) {
      await renderRevocation();
    }
  } catch (_e) {
    setAlert('error', 'Revocation update failed');
  } finally {
    state.revocationDecisionPending = false;
    syncRevocationRequestModal();
  }
}

// mise à jour des éléments de l'état réseau
async function refreshNetworkStatus() {
  const j = await apiGet('/api/network/status');
  state.network = j.data ? j.data : null;
  updateNetworkStatusPanels();
}

// remplace le contenu principal d'une page
function setView(html) {
  document.getElementById('view').innerHTML = html;
}

// code HTML de la page sign in 
function renderSignIn() {
  state.currentView = 'signin';
  setAlert(null, null);
  const defaults = defaultSigninCredentials();
  setView(`
    <div class="row">
      <div class="col-md-6 col-lg-5">
        <h4>Sign in</h4>
        <div class="mb-3">
          <label class="form-label">Login</label>
          <input class="form-control" id="signin-login" autocomplete="username" value="${escapeHtml(defaults.login)}">
        </div>
        <div class="mb-3">
          <label class="form-label">Password</label>
          <input class="form-control" id="signin-password" type="password" autocomplete="current-password" value="${escapeHtml(defaults.password)}">
        </div>
        <button class="btn btn-primary" id="signin-btn">Sign in</button>
        ${networkStatusHtml()}
      </div>
    </div>
  `);

  const submit = async () => {
    setAlert(null, null);
    const login = document.getElementById('signin-login').value.trim();
    const password = document.getElementById('signin-password').value;
    const j = await apiPost('/api/signin', { login, password });
    if (!j.ok) {
      setAlert('error', j.message || 'Sign in failed');
      return;
    }
    state.me = j.data;
    await refreshNetworkStatus();
    setNav();
    await refreshPresets();
    if (state.me.is_authority_user) {
      await refreshArl();
    }
    renderAuthedHome();
  };
  document.getElementById('signin-btn').onclick = submit;
  document.getElementById('signin-login').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') submit();
  });
  document.getElementById('signin-password').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') submit();
  });
}

// code HTML de la page sign up
function renderSignUp() {
  state.currentView = 'signup';
  setAlert(null, null);
  const defaults = defaultSigninCredentials();
  const clearance = defaultSignupClearance();
  const clearanceJson = JSON.stringify(clearance, null, 2);
  setView(`
    <div class="row">
      <div class="col-md-8 col-lg-7">
        <h4>Sign up</h4>
        <div class="mb-3">
          <label class="form-label">Login</label>
          <input class="form-control" id="signup-login" autocomplete="username" value="${escapeHtml(defaults.login)}">
        </div>
        <div class="mb-3">
          <label class="form-label">Password</label>
          <input class="form-control" id="signup-password" type="password" autocomplete="new-password" value="${escapeHtml(defaults.password)}">
        </div>
        <div class="mb-3">
          <label class="form-label">Clearance (JSON)</label>
          <textarea class="form-control" id="signup-clearance" rows="4">${escapeHtml(clearanceJson)}</textarea>
        </div>
        <button class="btn btn-primary" id="signup-btn">Create account</button>
        ${networkStatusHtml()}
      </div>
    </div>
  `);

  const submit = async () => {
    setAlert(null, null);
    const login = document.getElementById('signup-login').value.trim();
    const password = document.getElementById('signup-password').value;
    const clearanceStr = document.getElementById('signup-clearance').value;
    let clearance;
    try {
      clearance = JSON.parse(clearanceStr);
    } catch (e) {
      setAlert('error', 'Invalid clearance JSON');
      return;
    }
    const j = await apiPost('/api/signup', { login, password, clearance });
    if (!j.ok) {
      setAlert('error', j.message || 'Sign up failed');
      return;
    }
    state.me = j.data;
    await refreshNetworkStatus();
    setNav();
    await refreshPresets();
    setAlert('success', j.message || 'Account created');
    renderAuthedHome();
  };
  document.getElementById('signup-btn').onclick = submit;
  document.getElementById('signup-login').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') submit();
  });
  document.getElementById('signup-password').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') submit();
  });
}

// affiche les classifications que l'utilisateur a le droit d'utiliser depuis le panel Labelling
function computeClassificationOptions() {
  const me = state.me;
  const cfg = state.presets;
  const levels = { 'FR-DR': 0, 'FR-S': 1 };
  const userLevel = levels[me.clearance.classification];
  const opts = [];

  const candidates = ['FR-DR', 'FR-S'];
  for (const c of candidates) {
    const docLevel = levels[c];
    let allowed = true;
    if (cfg && cfg.nowriteup && docLevel > userLevel) allowed = false;
    if (cfg && cfg.nowritedown && docLevel < userLevel) allowed = false;
    if (allowed) opts.push(c);
  }

  return opts.length ? opts : [me.clearance.classification];
}

// affiche la/les mission(s) que l'utilisateur peut utiliser pour chiffrer depuis Labelling
function computeMissionOptions() {
  if (!state.me) return [];
  if (state.me.is_authority_user) return ['M1', 'M2'];
  return [state.me.clearance.mission];
}

function missionCheckboxHtml(mission, idPrefix) {
  const id = `${idPrefix}-${mission.toLowerCase()}`;
  return `
    <div class="form-check">
      <input class="form-check-input" type="checkbox" value="${escapeHtml(mission)}" id="${escapeHtml(id)}" data-revocation-mission>
      <label class="form-check-label" for="${escapeHtml(id)}">${escapeHtml(mission)}</label>
    </div>
  `;
}

function selectedRevocationMissions(containerId) {
  const container = document.getElementById(containerId);
  if (!container) return [];
  return Array.from(container.querySelectorAll('input[data-revocation-mission]:checked'))
    .map((input) => input.value);
}

function connectedNodesHtml(flush = false) {
  const className = flush ? 'connected-nodes-panel' : 'mt-3 connected-nodes-panel';
  return `<div class="${className}">${connectedNodesContentHtml()}</div>`;
}

function connectedNodesContentHtml() {
  if (!state.network || !state.network.enabled) return '';
  const userLine = state.me
    ? `${escapeHtml(state.me.login)} (${escapeHtml(state.me.clearance.classification)}, ${escapeHtml(state.me.clearance.mission)})`
    : escapeHtml(state.network.node_id || 'guest');
  const nodes = Array.isArray(state.network.connected_nodes) ? state.network.connected_nodes : [];
  const lines = nodes.map((node) => {
    const rawName = node.name || '';
    const displayName = node.is_authority ? rawName : rawName.toLowerCase();
    const name = escapeHtml(displayName);
    if (node.is_authority) return name;
    if (node.classification && node.mission) {
      return `${name} (${escapeHtml(node.classification)}, ${escapeHtml(node.mission)})`;
    }
    return name;
  });

  return `
    <div><strong>User</strong></div>
    <div>${userLine}</div>
    <div class="mt-3"><strong>Connected nodes</strong></div>
    ${lines.length
      ? `<div>${lines.join('<br>')}</div>`
      : `<div class="text-muted">No other connected nodes</div>`}
  `;
}

function updateConnectedNodesPanels() {
  document.querySelectorAll('.connected-nodes-panel').forEach((el) => {
    el.innerHTML = connectedNodesContentHtml();
  });
}

function updateNetworkStatusPanels() {
  document.querySelectorAll('.network-status-panel').forEach((el) => {
    el.innerHTML = networkStatusContentHtml(el.getAttribute('data-network-status-flush') === '1');
  });
  updateConnectedNodesPanels();
}

// affiche le statut réseau (net1-net2) sur la page HTML
function networkStatusHtml(flush = false) {
  if (!state.network || !state.network.enabled) return '';
  const className = flush ? 'network-status-panel' : 'mt-3 network-status-panel';
  const flushAttr = flush ? ' data-network-status-flush="1"' : '';
  return `<div class="${className}"${flushAttr}>${networkStatusContentHtml(flush)}</div>`;
}

function networkStatusContentHtml(flush = false) {
  if (!state.network || !state.network.enabled) return '';
  return connectedNodesHtml(flush);
}

// affiche la page HTML Labelling
function renderLabelling() {
  if (!state.me) {
    renderDefaultAuthView();
    return;
  }
  state.currentView = 'labelling';
  setAlert(null, null);

  if (!canUseLabelling()) {
    const hasDelegatedAccess = hasDelegatedAccessReady();
    setView(`
      <div class="row">
        <div class="col-lg-8">
          <h4>Labelling</h4>
        <div class="alert ${hasDelegatedAccess ? 'alert-info' : 'alert-warning'}">
          ${hasDelegatedAccess
            ? 'Delegated key material received. Document access is active now, but encryption still requires the ABS key.'
            : 'Encryption is unavailable until ABS key delivery completes.'}
        </div>
        <div class="text-muted">
          ${hasDelegatedAccess
            ? 'Delegation from another node completed successfully. You can already use the Documents view while waiting for Authority to deliver the ABS key.'
            : 'Waiting for key generation or delegation process.'}
        </div>
        </div>
        <div class="col-lg-4">
          <h4>Status</h4>
          <div class="card"><div class="card-body">
            <div><strong>User</strong>: ${escapeHtml(displayUserName())}</div>
            ${networkStatusHtml()}
          </div></div>
        </div>
      </div>
    `);
    return;
  }

  const classOpts = computeClassificationOptions();
  const missionOpts = computeMissionOptions();

  const classOptionsHtml = classOpts.map(x => `<option value="${escapeHtml(x)}">${escapeHtml(x)}</option>`).join('');
  const missionOptionsHtml = missionOpts.map(x => `<option value="${escapeHtml(x)}">${escapeHtml(x)}</option>`).join('');

  setView(`
    <div class="row">
      <div class="col-lg-8">
        <h4>Labelling</h4>
        <div class="mb-3">
          <label class="form-label">Message</label>
          <textarea class="form-control" id="encrypt-message" rows="7"></textarea>
        </div>
        <div class="row">
          <div class="col-md-4 mb-3">
            <label class="form-label">Classification</label>
            <select class="form-select" id="encrypt-classification">${classOptionsHtml}</select>
          </div>
          <div class="col-md-4 mb-3">
            <label class="form-label">Mission</label>
            <select class="form-select" id="encrypt-mission">${missionOptionsHtml}</select>
          </div>
        </div>
        <button class="btn btn-primary" id="encrypt-btn">Encrypt</button>
      </div>
      <div class="col-lg-4">
        <h4>Status</h4>
          <div class="card">
          <div class="card-body">
            <div><strong>User</strong>: ${escapeHtml(displayUserName())}</div>
            ${state.me.is_authority ? '' : `<div><strong>Clearance</strong>: ${escapeHtml(state.me.clearance.classification)} / ${escapeHtml(state.me.clearance.mission)}</div>`}
            ${networkStatusHtml()}
          </div>
        </div>
      </div>
    </div>
  `);

  document.getElementById('encrypt-btn').onclick = async () => {
    setAlert(null, null);
    const message = document.getElementById('encrypt-message').value;
    const classification = document.getElementById('encrypt-classification').value;
    const mission = document.getElementById('encrypt-mission').value;

    const j = await apiPost('/api/encrypt', { message, classification, mission });
    if (!j.ok) {
      setAlert('error', j.message || 'Encrypt failed');
      return;
    }
    setAlert('success', `Encrypted as ${j.data.id}.ct`);
    document.getElementById('encrypt-message').value = '';
  };
}

function renderConnectedPanel() {
  if (!state.me) {
    renderDefaultAuthView();
    return;
  }
  state.currentView = 'connected';
  setAlert(null, null);

  const hasDelegatedAccess = hasDelegatedAccessReady();
  const documentsReady = canUseDocuments();
  setView(`
    <div class="row">
      <div class="col-lg-8">
        <h4>Connected Panel</h4>
        <div class="alert ${hasDelegatedAccess ? 'alert-info' : 'alert-warning'}">
          ${hasDelegatedAccess
            ? 'Delegated key material received. Document access is active now. Encryption stays unavailable until the ABS key arrives.'
            : 'Waiting for key generation or delegation process.'}
        </div>
        <div class="card">
          <div class="card-body">
            <div><strong>User</strong>: ${escapeHtml(displayUserName())}</div>
            ${state.me.is_authority ? '' : `<div><strong>Clearance</strong>: ${escapeHtml(state.me.clearance.classification)} / ${escapeHtml(state.me.clearance.mission)}</div>`}
            ${keyReceptionStatusHtml()}
            ${hasDelegatedAccess ? `
              <div class="mt-3 text-muted">
                The Documents view is available right now. The Labelling tab will appear automatically when the ABS key is delivered.
              </div>
            ` : ''}
            <div id="connected-documents-summary"></div>
            ${documentsReady ? `<div class="mt-3">
              <button class="btn btn-outline-secondary" id="connected-documents">Open Documents</button>
            </div>` : ''}
          </div>
        </div>
      </div>
      <div class="col-lg-4">
        <h4>Status</h4>
        <div class="card">
          <div class="card-body">
            <div><strong>User</strong>: ${escapeHtml(displayUserName())}</div>
            ${networkStatusHtml()}
          </div>
        </div>
      </div>
    </div>
  `);

  populateConnectedDocumentsSummary();
  const documentsButton = document.getElementById('connected-documents');
  if (documentsButton) {
    documentsButton.onclick = () => renderDocuments();
  }
}

function documentStatus(doc) {
  return doc.status || 'viewable';
}

function documentActionButtonHtml(doc) {
  const id = escapeHtml(doc.id);
  const status = documentStatus(doc);
  if (status === 'revoked') {
    return '<button class="btn btn-sm btn-outline-danger" disabled>Revoked</button>';
  }
  if (status !== 'viewable') {
    return '<button class="btn btn-sm btn-secondary" disabled>View</button>';
  }
  return `<button class="btn btn-sm btn-secondary" data-docid="${id}">View</button>`;
}

// affiche la page HTML Documents
async function renderDocuments() {
  if (!state.me) {
    renderDefaultAuthView();
    return;
  }
  if (!canUseDocuments()) {
    renderConnectedPanel();
    return;
  }
  state.currentView = 'documents';
  setAlert(null, null);

  const j = await apiGet('/api/documents');
  if (!j.ok) {
    setAlert('error', j.message || 'Failed to load documents');
    return;
  }
  const docs = j.data.documents;

  const rows = docs.map(d => {
    return `
      <tr>
        <td>${d.id}</td>
        <td>${escapeHtml(d.label.classification)}</td>
        <td>${escapeHtml(d.label.mission)}</td>
        <td>${documentActionButtonHtml(d)}</td>
      </tr>
      <tr>
        <td colspan="4">
          <div class="border rounded p-2 bg-light" id="doc-out-${d.id}" style="display:none;"></div>
        </td>
      </tr>
    `;
  }).join('');

  setView(`
    <div class="row">
      <div class="col-lg-8">
        <h4>Documents</h4>
        <table class="table table-striped">
          <thead>
            <tr><th>ID</th><th>Classification</th><th>Mission</th><th>Action</th></tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
      <div class="col-lg-4">
        <h4>Status</h4>
        <div class="card">
          <div class="card-body">
            ${networkStatusHtml(true)}
          </div>
        </div>
      </div>
    </div>
  `);

  document.querySelectorAll('button[data-docid]').forEach(btn => {
    btn.onclick = async () => {
      setAlert(null, null);
      const id = Number(btn.getAttribute('data-docid'));
      const outEl = document.getElementById(`doc-out-${id}`);
      outEl.style.display = 'block';
      outEl.innerText = 'Decrypting...';
      const r = await apiPost('/api/decrypt', { id });
      if (!r.ok) {
        outEl.innerText = r.message || 'Decrypt failed';
        return;
      }
      outEl.innerText = r.data.message;
    };
  });
}

// affiche la page HTML révocation. Si utilisateur -> renderRevocationRequest()
async function renderRevocation() {
  if (!state.me) {
    renderDefaultAuthView();
    return;
  }
  if (state.me.is_authority) {
    renderArl();
    return;
  }
  if (!canUseRevocation()) {
    renderConnectedPanel();
    return;
  }
  if (!state.me.is_authority_user) {
    return renderRevocationRequest();
  }
  state.currentView = 'revocation';
  setAlert(null, null);
  await refreshArl();
  await refreshRevocationQueue();

  const revoked = (state.arl && state.arl.items) ? state.arl.items.filter(x => x.attribute_type === 'mission').map(x => x.attribute_value) : [];
  const queueRows = state.revocationQueue.map((x) => `
    <tr>
      <td>${x.id}</td>
      <td>${escapeHtml(x.requester)}</td>
      <td>${x.missions.map(m => escapeHtml(m)).join(', ')}</td>
      <td class="d-flex gap-2">
        <button class="btn btn-sm btn-success" data-approve-id="${x.id}">Accept</button>
        <button class="btn btn-sm btn-outline-danger" data-reject-id="${x.id}">Reject</button>
      </td>
    </tr>
  `).join('');

  setView(`
    <div class="row">
      <div class="col-lg-8">
        <h4>Revocation</h4>
        <h5>Pending Requests</h5>
        <table class="table table-sm mb-4">
          <thead>
            <tr><th>ID</th><th>User</th><th>Missions</th><th>Actions</th></tr>
          </thead>
          <tbody>${queueRows || '<tr><td colspan="4">No pending requests</td></tr>'}</tbody>
        </table>

        <h5>Direct Authority Revocation</h5>
        <div class="mb-3" id="revoke-mission-options">
          ${computeMissionOptions().map((mission) => missionCheckboxHtml(mission, 'revoke')).join('')}
        </div>
        <button class="btn btn-danger" id="revoke-btn">Revoke selected missions</button>

        <hr>

        <h5>Current ARL</h5>
        <ul class="list-group" id="arl-list"></ul>
      </div>
      <div class="col-lg-4">
        <h4>Status</h4>
        <div class="card">
          <div class="card-body">
            <div><strong>User</strong>: ${escapeHtml(displayUserName())}</div>
            ${networkStatusHtml()}
          </div>
        </div>
      </div>
    </div>
  `);

  const arlList = document.getElementById('arl-list');
  if (revoked.length === 0) {
    arlList.innerHTML = `<li class="list-group-item">Empty</li>`;
  } else {
    arlList.innerHTML = revoked.map(m => `<li class="list-group-item">mission: ${escapeHtml(m)}</li>`).join('');
  }

  document.getElementById('revoke-btn').onclick = async () => {
    setAlert(null, null);
    const missions = selectedRevocationMissions('revoke-mission-options');

    if (missions.length === 0) {
      setAlert('error', 'Select at least one mission');
      return;
    }
    const ok = window.confirm('Do you want to revoke this/these mission(s)?');
    if (!ok) return;

    const r = await apiPost('/api/revoke', { missions });
    if (!r.ok) {
      setAlert('error', r.message || 'Revoke failed');
      return;
    }
    setAlert('success', 'Revocation updated');
    await renderRevocation();
  };

  document.querySelectorAll('button[data-approve-id]').forEach((btn) => {
    btn.onclick = async () => {
      const id = Number(btn.getAttribute('data-approve-id'));
      const r = await apiPost('/api/revocation/approve', { id, approve: true });
      if (!r.ok) {
        setAlert('error', r.message || 'Approve failed');
        return;
      }
      setAlert('success', r.message || 'Revocation approved');
      await renderRevocation();
      syncRevocationRequestModal();
    };
  });

  document.querySelectorAll('button[data-reject-id]').forEach((btn) => {
    btn.onclick = async () => {
      const id = Number(btn.getAttribute('data-reject-id'));
      const r = await apiPost('/api/revocation/approve', { id, approve: false });
      if (!r.ok) {
        setAlert('error', r.message || 'Reject failed');
        return;
      }
      setAlert('success', r.message || 'Revocation rejected');
      await renderRevocation();
      syncRevocationRequestModal();
    };
  });

  syncRevocationRequestModal();
}

// affiche la page révocation pour un utilisateur
async function renderRevocationRequest() {
  if (!state.me || state.me.is_authority_user || state.me.is_authority || !canUseRevocation()) {
    renderConnectedPanel();
    return;
  }
  state.currentView = 'revocation';
  setAlert(null, null);
  const revocableMissions = [state.me.clearance.mission];
  setView(`
    <div class="row">
      <div class="col-lg-7">
        <h4>Ask Revocation</h4>
        <p class="text-muted">Request authority validation for mission revocation.</p>
        <div class="mb-3" id="ask-revoke-mission-options">
          ${revocableMissions.map((mission) => missionCheckboxHtml(mission, 'ask-revoke')).join('')}
        </div>
        <button class="btn btn-warning" id="ask-revoke-btn">AskRevocation</button>
      </div>
      <div class="col-lg-5">
        <h4>Status</h4>
        <div class="card">
          <div class="card-body">
            <div><strong>User</strong>: ${escapeHtml(displayUserName())}</div>
            ${networkStatusHtml()}
          </div>
        </div>
      </div>
    </div>
  `);
  document.getElementById('ask-revoke-btn').onclick = async () => {
    if (state.revocationRequestPending) return;
    const missions = selectedRevocationMissions('ask-revoke-mission-options');
    if (!missions.length) {
      setAlert('error', 'Select at least one mission');
      return;
    }
    const btn = document.getElementById('ask-revoke-btn');
    state.revocationRequestPending = true;
    btn.disabled = true;
    btn.textContent = 'Sending...';
    try {
      const r = await apiPost('/api/revocation/request', { missions });
      if (!r.ok) {
        setAlert('error', r.message || 'Request failed');
        return;
      }
      setAlert('success', r.message || 'Request sent');
    } catch (_e) {
      setAlert('error', 'Request failed');
    } finally {
      state.revocationRequestPending = false;
      const currentBtn = document.getElementById('ask-revoke-btn');
      if (currentBtn) {
        currentBtn.disabled = false;
        currentBtn.textContent = 'AskRevocation';
      }
    }
  };
}

// affiche la page des presets pour l'autorité 
async function renderPresets() {
  if (!state.me || !state.me.is_authority_user) {
    renderDefaultAuthView();
    return;
  }
  state.currentView = 'presets';
  setAlert(null, null);
  await refreshPresets();

  const cfg = state.presets;

  setView(`
    <div class="row">
      <div class="col-lg-6">
        <h4>Presets (BLP/Biba)</h4>
        <div class="form-check">
          <input class="form-check-input" type="checkbox" id="p-nru" ${cfg.noreadup ? 'checked' : ''}>
          <label class="form-check-label" for="p-nru">No Read Up (NRU)</label>
        </div>
        <div class="form-check">
          <input class="form-check-input" type="checkbox" id="p-nrd" ${cfg.noreaddown ? 'checked' : ''}>
          <label class="form-check-label" for="p-nrd">No Read Down (NRD)</label>
        </div>
        <div class="form-check">
          <input class="form-check-input" type="checkbox" id="p-nwu" ${cfg.nowriteup ? 'checked' : ''}>
          <label class="form-check-label" for="p-nwu">No Write Up (NWU)</label>
        </div>
        <div class="form-check">
          <input class="form-check-input" type="checkbox" id="p-nwd" ${cfg.nowritedown ? 'checked' : ''}>
          <label class="form-check-label" for="p-nwd">No Write Down (NWD)</label>
        </div>
        <div class="mt-3">
          <button class="btn btn-primary" id="presets-save">Save</button>
        </div>
      </div>
      <div class="col-lg-4">
        <h4>Status</h4>
        <div class="card">
          <div class="card-body">
            <div><strong>User</strong>: ${escapeHtml(displayUserName())}</div>
            ${networkStatusHtml()}
          </div>
        </div>
      </div>
    </div>
  `);

  document.getElementById('presets-save').onclick = async () => {
    setAlert(null, null);
    const nowriteup = document.getElementById('p-nwu').checked;
    const noreadup = document.getElementById('p-nru').checked;
    const nowritedown = document.getElementById('p-nwd').checked;
    const noreaddown = document.getElementById('p-nrd').checked;

    const r = await apiPost('/api/presets', { nowriteup, noreadup, nowritedown, noreaddown });
    if (!r.ok) {
      setAlert('error', r.message || 'Update presets failed');
      return;
    }
    state.presets = r.data;
    setAlert('success', 'Presets updated');
  };
}

// affiche la page HTML de l'ARL pour l'autorité
async function renderArl() {
  if (!state.me) {
    renderDefaultAuthView();
    return;
  }
  if (!state.me.is_authority) {
    renderLabelling();
    return;
  }
  state.currentView = 'arl';
  setAlert(null, null);
  await refreshArl();

  const items = (state.arl && state.arl.items) ? state.arl.items : [];
  const rows = items.map((x) => `
    <tr>
      <td>${escapeHtml(x.attribute_type)}</td>
      <td>${escapeHtml(x.attribute_value)}</td>
      <td>
        ${x.attribute_type === 'mission' ? `<button class="btn btn-sm btn-outline-success" data-unrevoke-mission="${escapeHtml(x.attribute_value)}">Unrevoke</button>` : ''}
      </td>
    </tr>
  `).join('');

  setView(`
    <div class="row">
      <div class="col-lg-8">
        <h4>ARL</h4>
        <table class="table table-sm table-striped">
          <thead>
            <tr><th>Type</th><th>Value</th><th>Actions</th></tr>
          </thead>
          <tbody>${rows || '<tr><td colspan="3">Empty</td></tr>'}</tbody>
        </table>
      </div>
      <div class="col-lg-4">
        <h4>Status</h4>
        <div class="card">
          <div class="card-body">
            <div><strong>User</strong>: ${escapeHtml(displayUserName())}</div>
            ${networkStatusHtml()}
          </div>
        </div>
      </div>
    </div>
  `);

  document.querySelectorAll('button[data-unrevoke-mission]').forEach((btn) => {
    btn.onclick = async () => {
      const mission = btn.getAttribute('data-unrevoke-mission');
      btn.disabled = true;
      const r = await apiPost('/api/unrevoke', { missions: [mission] });
      if (!r.ok) {
        setAlert('error', r.message || 'Unrevoke failed');
        btn.disabled = false;
        return;
      }
      state.arl = r.data;
      await renderArl();
      setAlert('success', `Mission ${mission} unrevoked`);
    };
  });

}

// décrit les éléments d'action dans la navbar lorsque l'on clique
function wireNav() {
  document.getElementById('nav-home').onclick = () => {
    if (state.me) renderAuthedHome();
    else renderDefaultAuthView();
  };
  document.getElementById('nav-labelling').onclick = () => renderLabelling();
  document.getElementById('nav-documents').onclick = () => renderDocuments();
  document.getElementById('nav-revocation').onclick = () => renderRevocation();
  document.getElementById('nav-presets').onclick = () => renderPresets();
  document.getElementById('nav-arl').onclick = () => renderArl();
}

// refresh l'état de l'application toutes les 500ms (valeur donnée dans init)
async function backgroundRefresh() {
  await refreshNetworkStatus();
  if (!state.me) return;
  const oldHasAbs = state.me.has_abs_key;
  const oldPendingKeyDelivery = state.me.pending_key_delivery;
  const oldHasDelegatedAccess = hasDelegatedAccessReady();
  await refreshMe();
  if (state.me && state.me.is_authority_user) {
    await refreshRevocationQueue();
    syncRevocationRequestModal();
  }
  const delegatedAccessChanged = oldHasDelegatedAccess !== hasDelegatedAccessReady();
  if (state.currentView === 'labelling' && (oldHasAbs !== state.me.has_abs_key || oldPendingKeyDelivery !== state.me.pending_key_delivery || delegatedAccessChanged)) {
    renderLabelling();
  } else if (state.currentView === 'connected' && (oldHasAbs !== state.me.has_abs_key || oldPendingKeyDelivery !== state.me.pending_key_delivery || delegatedAccessChanged)) {
    renderAuthedHome();
  } else if (state.currentView === 'arl' && !state.me.is_authority) {
    renderLabelling();
  } else if (state.currentView === 'revocation') {
    if (state.me.is_authority) {
      await renderArl();
    } else if (!canUseRevocation()) {
      renderAuthedHome();
    } else if (state.me.is_authority_user) {
      await renderRevocation();
    }
  }
}

// fonction de démarrage de l'IHM
async function init() {
  wireNav();
  await refreshMe();
  await refreshNetworkStatus();
  if (state.me) {
    await refreshPresets();
    if (state.me.is_authority_user) {
      await refreshArl();
      await refreshRevocationQueue();
    }
    renderAuthedHome();
  } else {
    renderDefaultAuthView();
  }
  setInterval(backgroundRefresh, 500);
}

init();
