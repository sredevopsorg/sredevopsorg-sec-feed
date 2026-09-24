// Security Intelligence Live Feed — frontend logic.
// Dependency-free: consumes the backend JSON API only.

(function () {
  const API_BASE = (window.__API_BASE_URL__ || "").replace(/\/+$/, "");
  const RECENT_LIMIT = 60;
  const ARCHIVE_LIMIT = 200;

  function api(path) {
    return API_BASE + path;
  }

  // mode: "recent" reads /api/feed (latest live refresh); "archive" reads
  // /api/items (the full persisted archive).
  const state = { items: [], tag: "", q: "", mode: "recent" };

  const $feed = document.getElementById("feed");
  const $count = document.getElementById("feedCount");
  const $errorNote = document.getElementById("errorNote");
  const $sampleNote = document.getElementById("sampleNote");
  const $livePill = document.getElementById("livePill");
  const $liveLabel = document.getElementById("liveLabel");
  const $fullFeedLink = document.getElementById("fullFeedLink");
  const $fullFeedLabel = document.getElementById("fullFeedLabel");

  function escapeHtml(value) {
    const div = document.createElement("div");
    div.textContent = value ?? "";
    return div.innerHTML;
  }

  // Only http(s) URLs become anchors; anything else (javascript:, data:, …)
  // is rendered as plain text.
  function safeHref(value) {
    if (!value) return "";
    try {
      const url = new URL(value, window.location.origin);
      return url.protocol === "http:" || url.protocol === "https:" ? url.href : "";
    } catch (_) {
      return "";
    }
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
    const href = safeHref(item.url);
    const title = href
      ? `<a class="row-title" href="${escapeHtml(href)}" target="_blank" rel="noopener noreferrer">${escapeHtml(item.title)}</a>`
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
    // Filtering happens server-side (tag/search query params); render what the
    // API returned so the two views can never disagree.
    const items = state.items;
    $count.textContent = `${items.length} item${items.length === 1 ? "" : "s"}`;
    if (!items.length) {
      $feed.innerHTML = `<div class="empty">No matching advisories right now.</div>`;
      return;
    }
    $feed.innerHTML = items.map(renderRow).join("");
  }

  function setLive(isLive) {
    $livePill.classList.toggle("offline", !isLive);
    $liveLabel.textContent = isLive ? "LIVE" : "OFFLINE";
    $livePill.title = isLive
      ? "Connected to the live feed"
      : "Feed unavailable — retrying";
  }

  function showSourceErrors(errors) {
    // Only /api/feed reports live-source errors; search/archive responses
    // leave the note untouched instead of clearing it with a stale message.
    if (!errors) return;
    if (errors.length) {
      $errorNote.hidden = false;
      const noun = errors.length === 1 ? "source" : "sources";
      const pronoun = errors.length === 1 ? "it" : "them";
      const extra = errors.length > 3 ? ` (+${errors.length - 3} more)` : "";
      // The feed is served from the store and stays current for every source
      // that answered, so do not claim the whole page is stale.
      $errorNote.textContent =
        `${errors.length} live ${noun} could not be reached in the last refresh; ` +
        `showing the most recent stored data for ${pronoun}. ` +
        errors.slice(0, 3).join(" · ") + extra;
    } else {
      $errorNote.hidden = true;
    }
  }

  function showSampleNote(items) {
    const sampleOnly = items.length > 0 && items.every(item => item.is_sample);
    $sampleNote.hidden = !sampleOnly;
    if (sampleOnly) {
      $sampleNote.textContent = "No live source is reachable right now — showing sample data.";
    }
  }

  function updateFooter() {
    const archive = state.mode === "archive";
    $fullFeedLabel.textContent = archive ? "Back to recent advisories" : "View full live feed";
    $fullFeedLink.title = archive
      ? "Show the most recent advisories"
      : "Open the full searchable archive";
  }

  async function loadFeed() {
    try {
      const archive = state.mode === "archive";
      const endpoint = state.q ? api("/api/search") : api(archive ? "/api/items" : "/api/feed");
      const url = new URL(endpoint, window.location.origin);
      url.searchParams.set("limit", String(archive ? ARCHIVE_LIMIT : RECENT_LIMIT));
      if (state.q) url.searchParams.set("q", state.q);
      if (state.tag) url.searchParams.set("tag", state.tag);
      const resp = await fetch(url);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      state.items = data.items || [];
      showSourceErrors(data.source_errors);
      showSampleNote(state.items);
      setLive(true);
      render();
    } catch (err) {
      setLive(false);
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

  $fullFeedLink.addEventListener("click", (event) => {
    event.preventDefault();
    state.mode = state.mode === "archive" ? "recent" : "archive";
    updateFooter();
    loadFeed();
  });

  function connectEvents() {
    const es = new EventSource(api('/api/events'));
    es.onopen = () => setLive(true);
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
      setLive(false);
    };
  }

  updateFooter();
  loadFeed();
  connectEvents();
  setInterval(loadFeed, 5 * 60 * 1000); // fallback poll every 5 minutes
})();
