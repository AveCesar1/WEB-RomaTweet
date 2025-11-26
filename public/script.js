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
