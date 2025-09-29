<script>
// Simple front-end logger for ACP actions
window.AuditLog = {
  send(event, details = {}) {
    return fetch("/audit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ event, details })
    }).then(r => r.json()).catch(() => ({}));
  }
};
</script>
