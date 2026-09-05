// Security Intelligence Live Feed — frontend logic.
// Dependency-free: consumes the backend JSON API only.

(function () {
  const API_BASE = (window.__API_BASE_URL__ || "").replace(/\/+$/, "");

  function api(path) {
    return API_BASE + path;
  }

  const state = { items: [], tag: "", q: "", lastSeen: new Set() };

  const $feed = document.getElementById("feed");
  const $count = document.getElementById("feedCount");
  const $errorNote = document.getElementById("errorNote");

  function escapeHtml(value) {
    const div = document.createElement("div");
    div.textContent = value ?? "";
    return div.innerHTML;
  }

  function chipClass(tag) {
    return `chip chip-${escapeHtml(tag)}`;
  }

  function renderRow(item) {
    const urgentDot = item.urgent
      ? `<span class="row-dot" title="Urgent / high priority"></span>`
      : `<span class="row-dot read" title="Read"></span>`;

    const chips = [];
    if (item.severity && item.severity !== "unknown") {
      chips.push(`<span class="chip chip-severity-${escapeHtml(item.severity)}">${escapeHtml(item.severity)}</span>`);
    }
    if (item.patch_status && item.patch_status !== "unknown") {
      chips.push(`<span class="chip chip-patch-status-${escapeHtml(item.patch_status)}">${escapeHtml(item.patch_status)}</span>`);
    }
    for (const tag of item.tags || []) {
      chips.push(`<span class="${chipClass(tag)}">${escapeHtml(tag)}</span>`);
    }

    const cveList = (item.cves || []).map(c => `<span class="chip chip-cve">${escapeHtml(c)}</span>`).join("");
    const title = item.url
      ? `<a class="row-title" href="${escapeHtml(item.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(item.title)}</a>`
      : `<span class="row-title">${escapeHtml(item.title)}</span>`;

    return `
      <article class="feed-row">
        <div class="row-time">${escapeHtml(item.time_ago)}</div>
        <div class="row-main">
          ${title}
          ${item.summary ? `<p class="row-summary">${escapeHtml(item.summary)}</p>` : ""}
          <div class="row-meta">${chips.join("")} ${cveList}</div>
          <div class="row-source">via ${escapeHtml(item.source)}</div>
        </div>
        ${urgentDot}
      </article>`;
  }

  function render() {
    const items = state.items.filter(i => !state.tag || (i.tags || []).includes(state.tag));
    $count.textContent = `${items.length} item${items.length === 1 ? "" : "s"}`;
    if (!items.length) {
      $feed.innerHTML = `<div class="empty">No matching advisories right now.</div>`;
      return;
    }
    $feed.innerHTML = items.map(renderRow).join("");
  }

  async function loadFeed() {
    try {
      const endpoint = state.q ? api("/api/search") : api("/api/feed");
      const url = new URL(endpoint, window.location.origin);
      url.searchParams.set("limit", "60");
      if (state.q) url.searchParams.set("q", state.q);
      if (state.tag) url.searchParams.set("tag", state.tag);
      const resp = await fetch(url);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      state.items = data.items || [];

      if (data.source_errors && data.source_errors.length) {
        $errorNote.hidden = false;
        $errorNote.textContent = "Some live sources are unreachable from this environment; showing cached/sample data. " +
          data.source_errors.slice(0, 3).join(" · ");
      } else {
        $errorNote.hidden = true;
      }
      render();
    } catch (err) {
      $errorNote.hidden = false;
      $errorNote.textContent = `Feed unavailable: ${err.message}. Retrying…`;
    }
  }

  document.getElementById("searchInput").addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      state.q = event.target.value.trim();
      loadFeed();
    }
  });
  document.getElementById("searchInput").addEventListener("search", (event) => {
    state.q = event.target.value.trim();
    loadFeed();
  });

  document.getElementById("filters").addEventListener("click", (event) => {
    const btn = event.target.closest("button[data-tag]");
    if (!btn) return;
    document.querySelectorAll(".filter-chip").forEach(b => b.classList.toggle("active", b === btn));
    state.tag = btn.dataset.tag || "";
    loadFeed();
  });

  document.getElementById("fullFeedLink").addEventListener("click", (event) => {
    event.preventDefault();
    const params = new URLSearchParams();
    if (state.tag) params.set("tag", state.tag);
    const qs = params.toString();
    alert("Full live feed would open the complete searchable archive" + (qs ? ` filtered by: ${state.tag}` : "") + ".");
  });

  function connectEvents() {
    const es = new EventSource(api('/api/events'));
    es.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.type === 'feed_updated') {
          loadFeed();
        }
      } catch (_) { /* ignore malformed events */ }
    };
    es.onerror = () => {
      // EventSource reconnects automatically; fallback polling below handles
      // environments where SSE is not available.
    };
  }

  loadFeed();
  connectEvents();
  setInterval(loadFeed, 5 * 60 * 1000); // fallback poll every 5 minutes
})();
