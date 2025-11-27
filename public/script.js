// public/script.js
document.addEventListener('DOMContentLoaded', function() {
  const postContent = document.getElementById('post-content');
  const charCount = document.getElementById('char-count');
  if (postContent && charCount) {
    postContent.addEventListener('input', function() {
      const remaining = 280 - this.value.length;
      charCount.textContent = `${remaining} caracteres restantes`;
      if (remaining < 0) charCount.classList.add('text-danger'); else charCount.classList.remove('text-danger');
    });
  }

  // No automatic prevention of form submission so server endpoints can work
});

function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/[&<>"']/g, function (m) {
    return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[m];
  });
}

function timeAgo(iso) {
  const d = new Date(iso);
  const diff = Date.now() - d.getTime();
  const sec = Math.floor(diff/1000);
  if (sec < 60) return sec + 's';
  const min = Math.floor(sec/60); if (min < 60) return min + 'm';
  const h = Math.floor(min/60); if (h < 24) return h + 'h';
  const days = Math.floor(h/24); return days + 'd';
}

// render single post card
function renderPost(post) {
  const avatar = post.avatar || 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgd2lkdGg9IjUwIiBoZWlnaHQ9IjUwIj48Y2lyY2xlIGN4PSIxMiIgY3k9IjEyIiByPSIxMiIgZmlsbD0iI2I4YTQ3ZSIvPjxjaXJjbGUgY3g9IjEyIiBjeT0iMTAiIHI9IjMiIGZpbGw9IiMzYTJjMWUiLz48cGF0aCBkPSJNMTIgMjFhOSA5IDAgMCAwIDktOSA3IDcgMCAwIDAtMTQgMCA5IDkgMCAwIDAgOSA5eiIgZmlsbD0iIzNhMmMxZSIvPjwvc3ZnPg==';
  return `
    <div class="card roman-card mb-3">
      <div class="card-body d-flex">
        <img src="${escapeHtml(avatar)}" class="rounded-circle me-3 user-avatar" alt="avatar">
        <div>
          <h6 class="author-text mb-0">${escapeHtml(post.full_name || post.username)} <span class="time-meta">@${escapeHtml(post.username)} · ${timeAgo(post.created_at)}</span></h6>
          <p class="golden-text mt-2 decorative-border">${escapeHtml(post.content)}</p>
          <div class="d-flex justify-content-between mt-3">
            <button class="btn roman-icon-btn"><i class="fas fa-comment"></i></button>
            <button class="btn roman-icon-btn"><i class="fas fa-retweet"></i></button>
            <button class="btn roman-icon-btn"><i class="fas fa-heart"></i></button>
            <button class="btn roman-icon-btn"><i class="fas fa-share"></i></button>
          </div>
        </div>
      </div>
    </div>
  `;
}

// fill left profile box
function renderLeftProfile(user, counts) {
  const avatar = user.avatar || 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgd2lkdGg9IjUwIiBoZWlnaHQ9IjUwIj48Y2lyY2xlIGN4PSIxMiIgY3k9IjEyIiByPSIxMiIgZmlsbD0iI2I4YTQ3ZSIvPjxjaXJjbGUgY3g9IjEyIiBjeT0iMTAiIHI9IjMiIGZpbGw9IiMzYTJjMWUiLz48cGF0aCBkPSJNMTIgMjFhOSA5IDAgMCAwIDktOSA3IDcgMCAwIDAtMTQgMCA5IDkgMCAwIDAgOSA5eiIgZmlsbD0iIzNhMmMxZSIvPjwvc3ZnPg==';
  const html = `
    <div class="card-body text-center">
      <img src="${escapeHtml(avatar)}" class="rounded-circle mb-3 user-avatar" alt="Avatar">
      <h5 class="author-text">${escapeHtml(user.full_name)}</h5>
      <p class="text-muted">@${escapeHtml(user.username)}</p>
      <div class="d-flex justify-content-around mt-3">
        <div class="text-center">
          <div class="stat-number">${counts.posts}</div>
          <div class="stat-label">Edictos</div>
        </div>
        <div class="text-center">
          <div class="stat-number">${counts.followers}</div>
          <div class="stat-label">Seguidores</div>
        </div>
      </div>
    </div>
  `;
  document.getElementById('left-profile').innerHTML = html;
  const compAvatar = document.getElementById('composer-avatar'); if (compAvatar) compAvatar.src = avatar;
}

// render top users sidebar
function renderTopUsers(users) {
  const container = document.querySelector('#sidebar-top-users .card-body');
  if (!container) return;
  if (!users || users.length === 0) {
    container.innerHTML = '<div class="text-muted">No hay cuentas recomendadas</div>';
    return;
  }
  container.innerHTML = users.map(u => `
    <div class="d-flex align-items-center mb-3">
      <img src="${escapeHtml(u.avatar || '')}" class="rounded-circle me-2 user-avatar" onerror="this.src='data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgd2lkdGg9IjQwIiBoZWlnaHQ9IjQwIj48Y2lyY2xlIGN4PSIxMiIgY3k9IjEyIiByPSIxMiIgZmlsbD0iI2I4YTQ3ZSIvPjxjaXJjbGUgY3g9IjEyIiBjeT0iMTAiIHI9IjMiIGZpbGw9IiMzYTJjMWUiLz48cGF0aCBkPSJNMTIgMjFhOSA5IDAgMCAwIDktOSA3IDcgMCAwIDAtMTQgMCA5IDkgMCAwIDAgOSA5eiIgZmlsbD0iIzNhMmMxZSIvPjwvc3ZnPg==' alt="Avatar">
      <div>
        <div class="author-text mb-0">${escapeHtml(u.full_name)}</div>
        <small class="text-muted">@${escapeHtml(u.username)} · ${u.followers_count || 0} seguidores</small>
      </div>
    </div>
  `).join('');
}

// initialize home page
async function initHome() {
  try {
    const [meRes, feedRes, topRes] = await Promise.all([
      fetch('/api/me'), fetch('/api/feed'), fetch('/api/users/top')
    ]);
    if (!meRes.ok) { if (meRes.status === 401) return window.location = '/'; }
    const me = await meRes.json();
    const feed = feedRes.ok ? await feedRes.json() : { posts: [] };
    const top = topRes.ok ? await topRes.json() : { users: [] };

    renderLeftProfile(me.user, me.counts || { posts:0, followers:0 });
    renderTopUsers(top.users || []);

    const feedContainer = document.getElementById('feed-container');
    if (feed.posts && feed.posts.length) {
      feedContainer.innerHTML = feed.posts.map(renderPost).join('');
    } else {
      feedContainer.innerHTML = '<div class="text-muted">No hay edictos todavía.</div>';
    }

    // wire new post form
    const form = document.getElementById('new-post-form');
    if (form) {
      form.addEventListener('submit', async function (e) {
        e.preventDefault();
        const content = document.getElementById('new-post-content').value;
        if (!content || !content.trim()) return alert('Contenido vacío');
        const r = await fetch('/api/me/posts', { method: 'POST', headers: { 'Content-Type':'application/json' }, body: JSON.stringify({ content }) });
        if (!r.ok) {
          const err = await r.json().catch(()=>({}));
          return alert('Error: ' + (err.error || 'no se pudo publicar'));
        }
        const data = await r.json();
        // prepend post
        feedContainer.insertAdjacentHTML('afterbegin', renderPost(Object.assign({}, data.post, { full_name: me.user.full_name, username: me.user.username, avatar: me.user.avatar })));
        document.getElementById('new-post-content').value = '';
      });
    }

  } catch (err) {
    console.error(err);
  }
}
