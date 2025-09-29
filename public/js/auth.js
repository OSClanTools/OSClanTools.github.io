<script>
(async function initAuthLink() {
  const link = document.getElementById("authLink");
  if (!link) return;
  try {
    const me = await fetch("/auth/me").then(r => r.json());
    if (me.loggedIn && me.isAdmin) {
      // Swap to ACP
      link.textContent = "ACP";
      link.href = "/admin";
      link.dataset.role = "acp";
    } else {
      // Show login
      link.textContent = "Login";
      link.href = "/auth/login";
      link.dataset.role = "login";
    }
  } catch {
    link.textContent = "Login";
    link.href = "/auth/login";
    link.dataset.role = "login";
  }
})();
</script>
