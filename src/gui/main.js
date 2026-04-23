const state = {
  me: null,
  presets: null,
  arl: null,
  network: null,
  revocationQueue: [],
  promptedRevocationIds: new Set(),
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
  const r = await fetch(path, { method: 'GET' });
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
  return state.me.is_admin || state.me.has_abs_key;
}

function hasDelegatedAccessReady() {
  if (!state.me || !state.network) return false;
  if (state.me.is_admin || state.me.is_authority) return false;
  return !!state.network.has_public_params
    && !!state.network.has_user_secret_key
    && !!state.network.has_tm_delegate_key
    && !state.me.has_abs_key;
}

function shouldShowLabellingNav() {
  if (!state.me) return false;
  if (state.me.is_authority || state.me.is_admin) return true;
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
  if (!container || !state.me || !hasDelegatedAccessReady()) return;

  container.innerHTML = '<div class="text-muted">Checking accessible documents...</div>';
  apiGet('/api/documents').then((j) => {
    const current = document.getElementById('connected-documents-summary');
    if (!current || state.currentView !== 'connected') return;

    if (!j.ok) {
      current.innerHTML = '<div class="text-danger">Could not load accessible documents.</div>';
      return;
    }

    const docs = (j.data && j.data.documents) ? j.data.documents : [];
    if (!docs.length) {
      current.innerHTML = `
        <div class="mt-3 text-muted">
          Delegation completed successfully. The Documents view is ready, but no compatible document is currently available.
        </div>
      `;
      return;
    }

    const preview = docs
      .slice(0, 5)
      .map((doc) => `<div>#${doc.id} (${escapeHtml(doc.label.classification)}, ${escapeHtml(doc.label.mission)})</div>`)
      .join('');

    current.innerHTML = `
      <div class="mt-3">
        <div><strong>Accessible documents now</strong>: ${docs.length}</div>
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
  const isAdmin = isAuthed && state.me.is_admin;
  const isAuthority = isAuthed && state.me.is_authority;

  document.getElementById('nav-labelling').parentElement.style.display = shouldShowLabellingNav() ? '' : 'none';
  document.getElementById('nav-documents').parentElement.style.display = isAuthed ? '' : 'none';
  document.getElementById('nav-revocation').parentElement.style.display = (isAuthed && !isAuthority) ? '' : 'none';
  document.getElementById('nav-presets').parentElement.style.display = isAdmin ? '' : 'none';
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
  if (!state.me || !state.me.is_admin) {
    state.arl = null;
    return;
  }
  const j = await apiGet('/api/revocations');
  state.arl = j.data ? j.data : null;
}

// recharge la liste des demandes de révocation en attente
async function refreshRevocationQueue() {
  if (!state.me || !state.me.is_admin) {
    state.revocationQueue = [];
    state.promptedRevocationIds.clear();
    return;
  }
  const j = await apiGet('/api/revocation/requests');
  state.revocationQueue = (j.ok && j.data && j.data.requests) ? j.data.requests : [];
  const liveIds = new Set(state.revocationQueue.map((x) => x.id));
  for (const id of Array.from(state.promptedRevocationIds)) {
    if (!liveIds.has(id)) {
      state.promptedRevocationIds.delete(id);
    }
  }
}

// mise à jour des éléments de l'état réseau
async function refreshNetworkStatus() {
  const j = await apiGet('/api/network/status');
  state.network = j.data ? j.data : null;
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
        ${connectivityControlsHtml()}
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
    if (state.me.is_admin) {
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
  if (document.getElementById('group-Net1')) {
    document.getElementById('group-Net1').onclick = () => setConnectivity('Net1');
    document.getElementById('group-Net2').onclick = () => setConnectivity('Net2');
  }
}

// code HTML de la page sign up
function renderSignUp() {
  state.currentView = 'signup';
  setAlert(null, null);
  const defaults = defaultSigninCredentials();
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
          <textarea class="form-control" id="signup-clearance" rows="4">{ "classification": "FR-DR", "mission": "M1" }</textarea>
        </div>
        <button class="btn btn-primary" id="signup-btn">Create account</button>
        ${connectivityControlsHtml()}
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
  if (document.getElementById('group-Net1')) {
    document.getElementById('group-Net1').onclick = () => setConnectivity('Net1');
    document.getElementById('group-Net2').onclick = () => setConnectivity('Net2');
  }
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
  if (state.me.is_admin) return ['M1', 'M2'];
  return [state.me.clearance.mission];
}

// permet de changer de groupe de connectivité depuis l'interface
async function setConnectivity(group) {
  const r = await apiPost('/api/network/group', { group });
  if (!r.ok) {
    setAlert('error', r.message || 'Failed to switch connectivity group');
    return;
  }
  state.network = r.data;
  if (state.me) {
    state.me.network_group = r.data.group;
  }
  setAlert('success', `Connectivity group set to ${r.data.group}`);
  if (state.currentView === 'labelling') {
    renderLabelling();
  } else if (state.currentView === 'signin') {
    renderSignIn();
  } else if (state.currentView === 'signup') {
    renderSignUp();
  } else if (state.currentView === 'documents') {
    await renderDocuments();
  }
}

// génère les boutons de changement de réseau
function connectivityControlsHtml() {
  if (!state.network || !state.network.enabled) return '';
  const current = state.network.group || (state.me ? state.me.network_group : null) || 'Net1';
  return `
    <div class="mt-3">
      <div class="mb-2"><strong>Connectivity</strong>: ${escapeHtml(current)}</div>
      <div class="btn-group" role="group">
        <button class="btn btn-outline-primary btn-sm" id="group-Net1" ${current === 'Net1' ? 'disabled' : ''}>Net1</button>
        <button class="btn btn-outline-primary btn-sm" id="group-Net2" ${current === 'Net2' ? 'disabled' : ''}>Net2</button>
      </div>
    </div>
  `;
}

function connectedNodesHtml() {
  if (!state.network || !state.network.enabled) return '';
  const nodes = Array.isArray(state.network.connected_nodes) ? state.network.connected_nodes : [];
  const lines = nodes.map((node) => {
    const name = escapeHtml(node.name || '');
    if (node.is_authority) return name;
    if (node.classification && node.mission) {
      return `${name} (${escapeHtml(node.classification)}, ${escapeHtml(node.mission)})`;
    }
    return name;
  });

  return `
    <div class="mt-3">
      <div><strong>Connected nodes</strong></div>
      ${lines.length
        ? `<div>${lines.join('<br>')}</div>`
        : `<div class="text-muted">No other connected nodes</div>`}
    </div>
  `;
}

// affiche le statut réseau (net1-net2) sur la page HTML
function networkStatusHtml() {
  if (!state.network || !state.network.enabled) return '';
  return `
    <div class="mt-3">
      ${connectedNodesHtml()}
    </div>
  `;
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
            ${connectivityControlsHtml()}
            ${networkStatusHtml()}
          </div></div>
        </div>
      </div>
    `);
    if (document.getElementById('group-Net1')) {
      document.getElementById('group-Net1').onclick = () => setConnectivity('Net1');
      document.getElementById('group-Net2').onclick = () => setConnectivity('Net2');
    }
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
            ${connectivityControlsHtml()}
            ${networkStatusHtml()}
          </div>
        </div>
      </div>
    </div>
  `);

  if (document.getElementById('group-Net1')) {
    document.getElementById('group-Net1').onclick = () => setConnectivity('Net1');
    document.getElementById('group-Net2').onclick = () => setConnectivity('Net2');
  }

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
            <div class="mt-3 text-muted">
              ${hasDelegatedAccess
                ? 'The Documents view is available right now. The Labelling tab will appear automatically when the ABS key is delivered.'
                : 'This panel will refresh automatically as soon as key material is received.'}
            </div>
            <div id="connected-documents-summary"></div>
            <div class="mt-3">
              <button class="btn btn-outline-secondary" id="connected-documents">Open Documents</button>
            </div>
          </div>
        </div>
      </div>
      <div class="col-lg-4">
        <h4>Status</h4>
        <div class="card">
          <div class="card-body">
            <div><strong>User</strong>: ${escapeHtml(displayUserName())}</div>
            ${connectivityControlsHtml()}
            ${networkStatusHtml()}
          </div>
        </div>
      </div>
    </div>
  `);

  if (document.getElementById('group-Net1')) {
    document.getElementById('group-Net1').onclick = () => setConnectivity('Net1');
    document.getElementById('group-Net2').onclick = () => setConnectivity('Net2');
  }
  populateConnectedDocumentsSummary();
  document.getElementById('connected-documents').onclick = () => renderDocuments();
}

// affiche la page HTML Documents
async function renderDocuments() {
  if (!state.me) {
    renderDefaultAuthView();
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
        <td><button class="btn btn-sm btn-secondary" data-docid="${d.id}">View</button></td>
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
            ${connectivityControlsHtml()}
            ${networkStatusHtml()}
          </div>
        </div>
      </div>
    </div>
  `);

  if (document.getElementById('group-Net1')) {
    document.getElementById('group-Net1').onclick = () => setConnectivity('Net1');
    document.getElementById('group-Net2').onclick = () => setConnectivity('Net2');
  }

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

// affiche la page HTML révocation. Si utilisateur -> renderRevocationRequest() et si authority -> renderArl()
async function renderRevocation() {
  if (!state.me) {
    renderDefaultAuthView();
    return;
  }
  if (state.me.is_authority) {
    renderLabelling();
    return;
  }
  if (!state.me.is_admin) {
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
        <div class="mb-3">
          <div class="form-check">
            <input class="form-check-input" type="checkbox" value="M1" id="revoke-m1">
            <label class="form-check-label" for="revoke-m1">M1</label>
          </div>
          <div class="form-check">
            <input class="form-check-input" type="checkbox" value="M2" id="revoke-m2">
            <label class="form-check-label" for="revoke-m2">M2</label>
          </div>
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
            ${connectivityControlsHtml()}
            ${networkStatusHtml()}
          </div>
        </div>
      </div>
    </div>
  `);

  if (document.getElementById('group-Net1')) {
    document.getElementById('group-Net1').onclick = () => setConnectivity('Net1');
    document.getElementById('group-Net2').onclick = () => setConnectivity('Net2');
  }

  const arlList = document.getElementById('arl-list');
  if (revoked.length === 0) {
    arlList.innerHTML = `<li class="list-group-item">Empty</li>`;
  } else {
    arlList.innerHTML = revoked.map(m => `<li class="list-group-item">mission: ${escapeHtml(m)}</li>`).join('');
  }

  document.getElementById('revoke-btn').onclick = async () => {
    setAlert(null, null);
    const missions = [];
    if (document.getElementById('revoke-m1').checked) missions.push('M1');
    if (document.getElementById('revoke-m2').checked) missions.push('M2');

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
    };
  });
}

// affiche la page révocation pour un utilisateur
async function renderRevocationRequest() {
  if (!state.me || state.me.is_admin || state.me.is_authority) {
    renderLabelling();
    return;
  }
  state.currentView = 'revocation';
  setAlert(null, null);
  setView(`
    <div class="row">
      <div class="col-lg-7">
        <h4>Ask Revocation</h4>
        <p class="text-muted">Request authority validation for mission revocation.</p>
        <div class="mb-3">
          <div class="form-check">
            <input class="form-check-input" type="checkbox" value="M1" id="ask-revoke-m1">
            <label class="form-check-label" for="ask-revoke-m1">M1</label>
          </div>
          <div class="form-check">
            <input class="form-check-input" type="checkbox" value="M2" id="ask-revoke-m2">
            <label class="form-check-label" for="ask-revoke-m2">M2</label>
          </div>
        </div>
        <button class="btn btn-warning" id="ask-revoke-btn">AskRevocation</button>
      </div>
      <div class="col-lg-5">
        <h4>Status</h4>
        <div class="card">
          <div class="card-body">
            <div><strong>User</strong>: ${escapeHtml(displayUserName())}</div>
            ${connectivityControlsHtml()}
            ${networkStatusHtml()}
          </div>
        </div>
      </div>
    </div>
  `);
  if (document.getElementById('group-Net1')) {
    document.getElementById('group-Net1').onclick = () => setConnectivity('Net1');
    document.getElementById('group-Net2').onclick = () => setConnectivity('Net2');
  }
  document.getElementById('ask-revoke-btn').onclick = async () => {
    const missions = [];
    if (document.getElementById('ask-revoke-m1').checked) missions.push('M1');
    if (document.getElementById('ask-revoke-m2').checked) missions.push('M2');
    const r = await apiPost('/api/revocation/request', { missions });
    if (!r.ok) {
      setAlert('error', r.message || 'Request failed');
      return;
    }
    setAlert('success', r.message || 'Request sent');
  };
}

// affiche la page des presets pour l'autorité 
async function renderPresets() {
  if (!state.me || !state.me.is_admin) {
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
            ${connectivityControlsHtml()}
            ${networkStatusHtml()}
          </div>
        </div>
      </div>
    </div>
  `);

  if (document.getElementById('group-Net1')) {
    document.getElementById('group-Net1').onclick = () => setConnectivity('Net1');
    document.getElementById('group-Net2').onclick = () => setConnectivity('Net2');
  }

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
    </tr>
  `).join('');

  setView(`
    <div class="row">
      <div class="col-lg-8">
        <h4>ARL</h4>
        <table class="table table-sm table-striped">
          <thead>
            <tr><th>Type</th><th>Value</th></tr>
          </thead>
          <tbody>${rows || '<tr><td colspan="2">Empty</td></tr>'}</tbody>
        </table>
      </div>
      <div class="col-lg-4">
        <h4>Status</h4>
        <div class="card">
          <div class="card-body">
            <div><strong>User</strong>: ${escapeHtml(displayUserName())}</div>
            ${connectivityControlsHtml()}
            ${networkStatusHtml()}
          </div>
        </div>
      </div>
    </div>
  `);

  if (document.getElementById('group-Net1')) {
    document.getElementById('group-Net1').onclick = () => setConnectivity('Net1');
    document.getElementById('group-Net2').onclick = () => setConnectivity('Net2');
  }
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
  if (!state.me) return;
  const oldHasAbs = state.me.has_abs_key;
  const oldPendingKeyDelivery = state.me.pending_key_delivery;
  const oldHasDelegatedAccess = hasDelegatedAccessReady();
  await refreshMe();
  await refreshNetworkStatus();
  if (state.me && state.me.is_admin) {
    await refreshRevocationQueue();
    for (const req of state.revocationQueue) {
      if (state.promptedRevocationIds.has(req.id)) continue;
      state.promptedRevocationIds.add(req.id);
      const ok = window.confirm(
        `Revocation request #${req.id} from ${req.requester} for [${req.missions.join(', ')}]. Accept?`
      );
      await apiPost('/api/revocation/approve', { id: req.id, approve: ok });
      break;
    }
  }
  const delegatedAccessChanged = oldHasDelegatedAccess !== hasDelegatedAccessReady();
  if (state.currentView === 'labelling' && (oldHasAbs !== state.me.has_abs_key || oldPendingKeyDelivery !== state.me.pending_key_delivery || delegatedAccessChanged)) {
    renderLabelling();
  } else if (state.currentView === 'connected' && (oldHasAbs !== state.me.has_abs_key || oldPendingKeyDelivery !== state.me.pending_key_delivery || delegatedAccessChanged)) {
    renderAuthedHome();
  } else if (state.currentView === 'arl') {
    if (state.me.is_authority) {
      await renderArl();
    } else {
      renderLabelling();
    }
  } else if (state.currentView === 'revocation') {
    if (state.me.is_admin && !state.me.is_authority) {
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
    if (state.me.is_admin) {
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
