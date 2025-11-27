// Profile page JS: replaces inline scripts in profile.html

document.addEventListener('DOMContentLoaded', async () => {
  try {
    const meResp = await fetch('/api/me', { credentials: 'same-origin' });
    if (meResp.status === 401) return window.location = '/';
    const meData = await meResp.json();
    const user = meData.user;
    const counts = meData.counts || {};

    // Left column: profile summary
    const left = document.querySelector('.col-md-4 .card.roman-card .card-body');
    if (left && user) {
      const img = left.querySelector('img');
      if (img && user.avatar) img.src = user.avatar;
      const h3 = left.querySelector('h3');
      if (h3) h3.textContent = user.full_name || user.username;
      const pUsername = left.querySelector('p');
      if (pUsername) pUsername.textContent = '@' + (user.username || '');
      const bio = left.querySelectorAll('p')[1];
      if (bio) bio.textContent = user.bio || '';
      // stats
      const stats = left.querySelectorAll('.text-center h5');
      if (stats && stats.length >= 3) {
        stats[0].textContent = counts.followers || 0;
        stats[1].textContent = counts.following || 0;
        stats[2].textContent = counts.posts || 0;
      }
    }

    // Posts: replace placeholder posts with real ones
    const postsContainer = document.querySelector('.col-md-8 .card.roman-card .card-body');
    if (postsContainer) {
      postsContainer.innerHTML = '';
      const postsResp = await fetch('/api/me/posts', { credentials: 'same-origin' });
      if (postsResp.status === 401) return window.location = '/';
      const postsData = await postsResp.json();
      const posts = postsData.posts || [];
      if (posts.length === 0) {
        postsContainer.innerHTML = '<p class="text-muted">No hay edictos aún.</p>';
      } else {
        for (const post of posts) {
          const postEl = document.createElement('div');
          postEl.className = 'post-item mb-4 pb-3 golden-border-bottom';
          postEl.innerHTML = `
            <div class="d-flex">
              <img src="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgd2lkdGg9IjUwIiBoZWlnaHQ9IjUwIj48Y2lyY2xlIGN4PSIxMiIgY3k9IjEyIiByPSIxMiIgZmlsbD0iI2I4YTQ3ZSIvPjxjaXJjbGUgY3g9IjEyIiBjeT0iMTAiIHI9IjMiIGZpbGw9IiMzYTJjMWUiLz48cGF0aCBkPSJNMTIgMjFhOSA5IDAgMCAwIDktOSA3IDcgMCAwIDAtMTQgMCA5IDkgMCAwIDAgOSA5eiIgZmlsbD0iIzNhMmMxZSIvPjwvc3ZnPg==" class="rounded-circle me-3 user-avatar" alt="Avatar">
              <div>
                <h6 class="author-text mb-0">${escapeHtml(user.full_name)} <span class="time-meta">@${escapeHtml(user.username)} · ${timeAgo(new Date(post.created_at))}</span></h6>
                <p class="golden-text mt-2 decorative-border">${escapeHtml(post.content)}</p>
              </div>
            </div>`;
          postsContainer.appendChild(postEl);
        }
      }
    }

  } catch (err) {
    console.error('Profile render error', err);
  }

  // render following list
  (async function renderFollowing(){
    try{
      const el = document.getElementById('following-list');
      const resp = await fetch('/api/me/following', { credentials: 'same-origin' });
      if (resp.status === 401) return window.location = '/';
      const data = await resp.json();
      const list = data.following || [];
      if (!el) return;
      if (list.length === 0) {
        el.innerHTML = '<p class="text-muted">No sigues a nadie todavía.</p>';
        return;
      }
      el.innerHTML = '';
      for (const u of list) {
        const item = document.createElement('div');
        item.className = 'd-flex align-items-center mb-3';
        item.innerHTML = `
          <img src="${u.avatar || 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgd2lkdGg9IjQwIiBoZWlnaHQ9IjQwIj48Y2lyY2xlIGN4PSIxMiIgY3k9IjEyIiByPSIxMiIgZmlsbD0iI2I4YTQ3ZSIvPjxjaXJjbGUgY3g9IjEyIiBjeT0iMTAiIHI9IjMiIGZpbGw9IiMzYTJjMWUiLz48cGF0aCBkPSJNMTIgMjFhOSA5IDAgMCAwIDktOSA3IDcgMCAwIDAtMTQgMCA5IDkgMCAwIDAgOSA5eiIgZmlsbD0iIzNhMmMxZSIvPjwvc3ZnPg=='}" class="rounded-circle me-2 user-avatar" alt="Avatar">
          <div>
            <h6 class="author-text mb-0">${escapeHtml(u.full_name || u.username)}</h6>
            <small class="text-muted">@${escapeHtml(u.username)}</small>
          </div>
        `;
        el.appendChild(item);
      }
    }catch(err){console.error(err)}
  })();

});

// tab handling (Tus Edictos / Me gusta / Respuestas)
(function wireTabs(){
  const tabs = document.querySelectorAll('.nav.nav-tabs .nav-link');
  if (!tabs || tabs.length === 0) return;
  const postsContainer = document.querySelector('.col-md-8 .card.roman-card .card-body');
  async function showMyPosts(){
    // reuse existing loaded posts if present by re-fetching
    postsContainer.innerHTML = '';
    const r = await fetch('/api/me/posts', { credentials: 'same-origin' });
    if (r.status === 401) return window.location = '/';
    const j = await r.json(); const posts = j.posts || [];
    if (posts.length === 0) postsContainer.innerHTML = '<p class="text-muted">No hay edictos aún.</p>';
    for (const post of posts) {
      const div = document.createElement('div'); div.className = 'post-item mb-4 pb-3 golden-border-bottom';
      div.innerHTML = `<div class="d-flex"><img src="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgd2lkdGg9IjUwIiBoZWlnaHQ9IjUwIj48Y2lyY2xlIGN4PSIxMiIgY3k9IjEyIiByPSIxMiIgZmlsbD0iI2I4YTQ3ZSIvPjxjaXJjbGUgY3g9IjEyIiBjeT0iMTAiIHI9IjMiIGZpbGw9IiMzYTJjMWUiLz48cGF0aCBkPSJNMTIgMjFhOSA5IDAgMCAwIDktOSA3IDcgMCAwIDAtMTQgMCA5IDkgMCAwIDAgOSA5eiIgZmlsbD0iIzNhMmMxZSIvPjwvc3ZnPg==" class="rounded-circle me-3 user-avatar" alt="Avatar"><div><h6 class="author-text mb-0">${escapeHtml(j.user && j.user.full_name || '')} <span class="time-meta">@${escapeHtml(j.user && j.user.username||'')} · ${timeAgo(new Date(post.created_at))}</span></h6><p class="golden-text mt-2 decorative-border">${escapeHtml(post.content)}</p></div></div>`;
      postsContainer.appendChild(div);
    }
  }
  async function showLikes(){
    postsContainer.innerHTML = '<p class="text-muted">Cargando edictos que te gustaron...</p>';
    const r = await fetch('/api/me/likes', { credentials: 'same-origin' });
    if (r.status === 401) return window.location = '/';
    const j = await r.json(); const posts = j.posts || [];
    postsContainer.innerHTML = '';
    if (posts.length === 0) postsContainer.innerHTML = '<p class="text-muted">No tienes edictos marcados con me gusta.</p>';
    // default avatar for liked messages (provided by the user)
    const defaultLikedAvatar = 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgd2lkdGg9IjUwIiBoZWlnaHQ9IjUwIj48Y2lyY2xlIGN4PSIxMiIgY3k9IjEyIiByPSIxMiIgZmlsbD0iI2Q0YmE0MCIvPjxjaXJjbGUgY3g9IjEyIiBjeT0iMTAiIHI9IjMiIGZpbGw9IiMxYTAwMDAiLz48cGF0aCBkPSJNMTIgMjFhOSA5IDAgMCAwIDktOSA3IDcgMCAwIDAtMTQgMCA5IDkgMCAwIDAgOSA5eiIgZmlsbD0iIzFhMDAwMCIvPjwvc3ZnPg==';
    for (const post of posts) {
      const div = document.createElement('div'); div.className = 'post-item mb-4 pb-3 golden-border-bottom';
      const avatarSrc = post.avatar || defaultLikedAvatar;
      div.innerHTML = `<div class="d-flex"><img src="${escapeHtml(avatarSrc)}" class="rounded-circle me-3 user-avatar" alt="Avatar"><div><h6 class="author-text mb-0">${escapeHtml(post.full_name||post.username)} <span class="time-meta">@${escapeHtml(post.username)} · ${timeAgo(new Date(post.created_at))}</span></h6><p class="golden-text mt-2 decorative-border">${escapeHtml(post.content)}</p></div></div>`;
      postsContainer.appendChild(div);
    }
  }
  async function showReplies(){
    postsContainer.innerHTML = '<p class="text-muted">Cargando tus respuestas...</p>';
    const r = await fetch('/api/me/replies', { credentials: 'same-origin' });
    if (r.status === 401) return window.location = '/';
    const j = await r.json(); const replies = j.replies || [];
    postsContainer.innerHTML = '';
    if (replies.length === 0) postsContainer.innerHTML = '<p class="text-muted">No has respondido a ningún edicto aún.</p>';
    for (const rep of replies) {
      const div = document.createElement('div'); div.className = 'post-item mb-4 pb-3 golden-border-bottom';
      div.innerHTML = `<div class="d-flex"><div class="me-3"><small class="text-muted">En respuesta a</small><p class="golden-text decorative-border">${escapeHtml(rep.post_content)}</p></div><div><small class="text-muted">Tu respuesta · ${timeAgo(new Date(rep.commented_at))}</small><p class="golden-text mt-2">${escapeHtml(rep.comment)}</p></div></div>`;
      postsContainer.appendChild(div);
    }
  }

  // attach click handlers
  tabs.forEach(tab => {
    tab.addEventListener('click', (e) => {
      e.preventDefault();
      tabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      const text = tab.textContent && tab.textContent.trim().toLowerCase();
      if (text.includes('tus edictos')) return showMyPosts();
      if (text.includes('me gusta') || text.includes('me gusta'.toLowerCase())) return showLikes();
      if (text.includes('respuestas')) return showReplies();
    });
  });
})();

// helpers
function escapeHtml(str){ if (!str) return ''; return String(str).replace(/[&<>'"]/g, s => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[s]); }
function timeAgo(d){ try{ const ms = Date.now() - new Date(d).getTime(); const sec = Math.floor(ms/1000); if (sec<60) return sec+'s'; const min=Math.floor(sec/60); if (min<60) return min+'m'; const hr=Math.floor(min/60); if (hr<24) return hr+'h'; const days=Math.floor(hr/24); return days+'d'; }catch(e){return ''} }
