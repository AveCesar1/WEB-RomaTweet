// Post page JS - moves inline script out of HTML

document.addEventListener('DOMContentLoaded', () => {
  const postForm = document.getElementById('new-post-form');
  const contentEl = document.getElementById('post-content');
  const charCount = document.getElementById('char-count');
  const recentEl = document.getElementById('recent-posts');

  // fetch profile and fill header
  fetch('/api/me', { credentials: 'same-origin' }).then(r => {
    if (r.status === 401) return window.location = '/';
    return r.json();
  }).then(data => {
    if (!data) return;
    const u = data.user;
    if (u) {
      const avatar = document.getElementById('profile-avatar');
      if (avatar && u.avatar) avatar.src = u.avatar;
      const fn = document.getElementById('profile-fullname'); if (fn) fn.textContent = u.full_name || u.username;
      const un = document.getElementById('profile-username'); if (un) un.textContent = '@' + (u.username || '');
    }
  }).catch(()=>window.location='/');

  // load recent posts
  async function loadPosts(){
    try{
      const r = await fetch('/api/me/posts', { credentials: 'same-origin' });
      if (r.status === 401) return window.location = '/';
      const j = await r.json();
      const posts = j.posts || [];
      recentEl.innerHTML = '';
      if (posts.length === 0) recentEl.innerHTML = '<p class="text-muted">No tienes edictos aún.</p>';
      for (const p of posts) {
        const div = document.createElement('div');
        div.className = 'post-preview mb-3 pb-3 golden-border-bottom';
        div.innerHTML = `<p class="golden-text decorative-border">${escapeHtml(p.content)}</p><small class="text-muted">${timeAgo(new Date(p.created_at))}</small>`;
        recentEl.appendChild(div);
      }
    }catch(e){console.error(e)}
  }

  loadPosts();

  postForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const content = contentEl.value || '';
    if (!content.trim()) return alert('El contenido no puede estar vacío');
    try{
      const r = await fetch('/api/me/posts', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content })
      });
      if (r.status === 401) return window.location = '/';
      const j = await r.json();
      if (j && j.post) {
        contentEl.value = '';
        loadPosts();
      } else {
        alert('Error al publicar');
      }
    }catch(err){console.error(err); alert('Error al publicar');}
  });

  // char counter
  if (contentEl && charCount) {
    contentEl.addEventListener('input', function(){
      const remaining = 280 - this.value.length;
      charCount.textContent = `${remaining} caracteres restantes`;
      if (remaining < 0) charCount.classList.add('text-danger'); else charCount.classList.remove('text-danger');
    });
  }
});

function escapeHtml(str){ if (!str) return ''; return String(str).replace(/[&<>\"']/g, s => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[s]); }
function timeAgo(d){ try{ const ms = Date.now() - new Date(d).getTime(); const sec = Math.floor(ms/1000); if (sec<60) return sec+'s'; const min=Math.floor(sec/60); if (min<60) return min+'m'; const hr=Math.floor(min/60); if (hr<24) return hr+'h'; const days=Math.floor(hr/24); return days+'d'; }catch(e){return ''} }
