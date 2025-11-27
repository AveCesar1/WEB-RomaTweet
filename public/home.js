// Home page JS: initHome is called from /views/home.html

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

// reuse helpers from global script.js (escapeHtml, renderPost, renderLeftProfile, renderTopUsers)
