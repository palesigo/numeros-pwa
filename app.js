'use strict';
const $ = s => document.querySelector(s);
const KEY = 'vault_v1';
const enc = new TextEncoder(), dec = new TextDecoder();
const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

let cryptoKey = null, salt = null, items = [], editingId = null;
const revealed = new Set();
let lockTimer = null;

/* ---------- Criptografia ---------- */
async function deriveKey(pass, saltBytes) {
  const base = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: saltBytes, iterations: 250000, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function persist() {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cryptoKey, enc.encode(JSON.stringify(items)));
  localStorage.setItem(KEY, JSON.stringify({ v: 1, salt: b64(salt), iv: b64(iv), data: b64(ct) }));
}
async function loadVault(pass) {
  const v = JSON.parse(localStorage.getItem(KEY));
  salt = unb64(v.salt);
  cryptoKey = await deriveKey(pass, salt);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(v.iv) }, cryptoKey, unb64(v.data));
  items = JSON.parse(dec.decode(pt));
}

/* ---------- Bloqueio ---------- */
function showLock() {
  cryptoKey = null; items = []; revealed.clear();
  $('#app').hidden = true;
  if ($('#dlg').open) $('#dlg').close();
  const first = !localStorage.getItem(KEY);
  $('#lock').hidden = false;
  $('#pass2').hidden = !first; $('#pass2').required = first;
  $('#lockMsg').textContent = first
    ? 'Define uma palavra-passe mestra (mín. 6 caracteres). Não há recuperação se a esqueceres.'
    : 'Introduz a palavra-passe para desbloquear.';
  $('#pass').value = ''; $('#pass2').value = ''; $('#lockErr').textContent = '';
}
$('#lockForm').addEventListener('submit', async e => {
  e.preventDefault();
  const pass = $('#pass').value, first = !localStorage.getItem(KEY);
  try {
    if (first) {
      if (pass !== $('#pass2').value) { $('#lockErr').textContent = 'As palavras-passe não coincidem.'; return; }
      salt = crypto.getRandomValues(new Uint8Array(16));
      cryptoKey = await deriveKey(pass, salt); items = []; await persist();
    } else {
      await loadVault(pass);
    }
    $('#lock').hidden = true; $('#app').hidden = false; render();
  } catch { $('#lockErr').textContent = 'Palavra-passe incorreta ou dados corrompidos.'; }
});
$('#btnLock').onclick = showLock;
document.addEventListener('visibilitychange', () => {
  clearTimeout(lockTimer);
  if (document.hidden && cryptoKey) lockTimer = setTimeout(showLock, 60000); // bloqueia após 1 min em segundo plano
});

/* ---------- Utilitários ---------- */
function h(tag, props = {}, ...kids) {
  const el = Object.assign(document.createElement(tag), props);
  kids.flat().forEach(k => el.append(k));
  return el;
}
function expiryInfo(date) {
  if (!date) return null;
  const days = Math.ceil((new Date(date + 'T23:59:59') - new Date()) / 864e5);
  const fmt = date.split('-').reverse().join('/');
  if (days < 0) return { cls: 'bad', txt: `Expirado (${fmt})` };
  if (days <= 90) return { cls: 'warn', txt: `Expira em ${days} d (${fmt})` };
  return { cls: '', txt: `Válido até ${fmt}` };
}
const mask = n => n.length > 4 ? '•'.repeat(n.length - 4) + n.slice(-4) : '••••';

/* ---------- Listagem ---------- */
function render() {
  const owners = [...new Set(items.map(i => i.owner))].sort();
  const sel = $('#filterOwner'), cur = sel.value;
  sel.replaceChildren(h('option', { value: '', textContent: 'Todos' }),
    ...owners.map(o => h('option', { value: o, textContent: o })));
  sel.value = owners.includes(cur) ? cur : '';
  $('#owners').replaceChildren(...owners.map(o => h('option', { value: o })));

  const q = $('#search').value.trim().toLowerCase();
  const list = items.filter(i =>
    (!sel.value || i.owner === sel.value) &&
    (!q || [i.owner, i.type, i.label, i.notes].join(' ').toLowerCase().includes(q)))
    .sort((a, b) => a.owner.localeCompare(b.owner) || a.type.localeCompare(b.type));

  $('#empty').hidden = items.length > 0;
  $('#list').replaceChildren(...list.map(card));
}
function card(i) {
  const name = i.type === 'Outro' && i.label ? i.label : i.type;
  const ex = expiryInfo(i.expiry), shown = revealed.has(i.id);
  return h('li', {},
    h('div', { className: 'top' },
      h('strong', { textContent: `${i.owner} · ${name}` }),
      ex ? h('span', { className: 'badge ' + ex.cls, textContent: ex.txt }) : ''),
    h('div', { className: 'num', textContent: shown ? i.number : mask(i.number) }),
    i.notes ? h('div', { className: 'top', textContent: i.notes }) : '',
    h('div', { className: 'actions' },
      h('button', { textContent: shown ? 'Ocultar' : 'Mostrar', onclick: () => { shown ? revealed.delete(i.id) : revealed.add(i.id); render(); } }),
      h('button', { textContent: 'Copiar', onclick: async e => {
        try { await navigator.clipboard.writeText(i.number); e.target.textContent = 'Copiado ✓'; setTimeout(render, 1200); } catch { alert('Não foi possível copiar.'); } } }),
      h('button', { textContent: 'Editar', onclick: () => openDialog(i) }),
      h('button', { textContent: 'Apagar', onclick: () => remove(i) })));
}
async function remove(i) {
  if (!confirm(`Apagar ${i.type} de ${i.owner}?`)) return;
  items = items.filter(x => x.id !== i.id); await persist(); render();
}
$('#search').oninput = render;
$('#filterOwner').onchange = render;

/* ---------- Formulário ---------- */
const toggleLabel = () => { $('#lblName').hidden = $('#fType').value !== 'Outro'; };
$('#fType').onchange = toggleLabel;
function openDialog(item) {
  editingId = item?.id ?? null;
  $('#dlgTitle').textContent = item ? 'Editar registo' : 'Novo registo';
  $('#fOwner').value = item?.owner ?? $('#filterOwner').value ?? '';
  $('#fType').value = item?.type ?? 'CC';
  $('#fLabel').value = item?.label ?? '';
  $('#fNumber').value = item?.number ?? '';
  $('#fExpiry').value = item?.expiry ?? '';
  $('#fNotes').value = item?.notes ?? '';
  toggleLabel(); $('#dlg').showModal();
}
$('#fab').onclick = () => openDialog();
$('#btnCancel').onclick = () => $('#dlg').close();
$('#form').addEventListener('submit', async () => {
  const rec = {
    id: editingId ?? crypto.randomUUID(),
    owner: $('#fOwner').value.trim(),
    type: $('#fType').value,
    label: $('#fType').value === 'Outro' ? $('#fLabel').value.trim() : '',
    number: $('#fNumber').value.trim(),
    expiry: $('#fExpiry').value,
    notes: $('#fNotes').value.trim()
  };
  if (!rec.owner || !rec.number) return;
  items = editingId ? items.map(x => x.id === editingId ? rec : x) : [...items, rec];
  await persist(); render();
});

/* ---------- Cópia de segurança (ficheiro cifrado) ---------- */
$('#btnExport').onclick = () => {
  const blob = new Blob([localStorage.getItem(KEY)], { type: 'application/json' });
  const a = h('a', { href: URL.createObjectURL(blob), download: `numeros-backup-${new Date().toISOString().slice(0, 10)}.json` });
  a.click(); URL.revokeObjectURL(a.href);
};
$('#btnImport').onclick = () => $('#importFile').click();
$('#importFile').onchange = async e => {
  const f = e.target.files[0]; if (!f) return;
  try {
    const v = JSON.parse(await f.text());
    if (!v.salt || !v.iv || !v.data) throw 0;
    if (!confirm('Isto substitui TODOS os dados atuais. Continuar? Terás de usar a palavra-passe do backup.')) return;
    localStorage.setItem(KEY, JSON.stringify(v)); showLock();
  } catch { alert('Ficheiro inválido.'); }
  e.target.value = '';
};

/* ---------- Arranque ---------- */
if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js');
showLock();
