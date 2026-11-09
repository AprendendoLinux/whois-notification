/* Whois Notification — comportamento da interface */
(function () {
  "use strict";

  const css = getComputedStyle(document.documentElement);
  const C = (name) => css.getPropertyValue(name).trim();
  const COLORS = {
    cyan: C("--cyan"), magenta: C("--magenta"), violet: C("--violet"),
    ok: C("--ok"), warn: C("--warn"), crit: C("--crit"), dead: C("--dead"), muted: C("--muted"),
    text: C("--text"), dim: C("--text-dim"), faint: C("--text-faint"), line: "rgba(0,229,255,0.14)",
  };
  const HEALTH_COLOR = {
    ok: COLORS.ok, warning: COLORS.warn, critical: COLORS.crit, expired: COLORS.dead,
    unknown: COLORS.muted, disabled: COLORS.muted,
  };
  const HEALTH_LABEL = {
    ok: "Operacional", warning: "Atenção", critical: "Crítico", expired: "Expirado",
    unknown: "Sem dados", disabled: "Pausado",
  };
  const FONT_MONO = "JetBrains Mono, monospace";
  const fmtDate = (d) => new Date(d).toLocaleDateString("pt-BR");

  // Relógio do topo (Alpine)
  window.clock = () => ({
    time: "", date: "",
    tick() {
      const upd = () => {
        const n = new Date();
        this.time = n.toLocaleTimeString("pt-BR");
        this.date = n.toLocaleDateString("pt-BR", { weekday: "short", day: "2-digit", month: "short", year: "numeric" });
      };
      upd();
      setInterval(upd, 1000);
    },
  });

  // Contagem regressiva ao vivo (Alpine)
  window.countdown = (iso) => ({
    d: "--", h: "--", m: "--", s: "--", expired: false,
    start() {
      if (!iso) return;
      const target = new Date(iso).getTime();
      const pad = (n) => String(n).padStart(2, "0");
      const upd = () => {
        let diff = Math.floor((target - Date.now()) / 1000);
        this.expired = diff < 0;
        diff = Math.abs(diff);
        this.d = Math.floor(diff / 86400);
        this.h = pad(Math.floor((diff % 86400) / 3600));
        this.m = pad(Math.floor((diff % 3600) / 60));
        this.s = pad(diff % 60);
      };
      upd();
      setInterval(upd, 1000);
    },
  });

  const charts = [];
  window.addEventListener("resize", () => charts.forEach((c) => c.resize()));
  function mount(id) {
    const el = document.getElementById(id);
    if (!el || !window.echarts) return null;
    const c = echarts.init(el, null, { renderer: "canvas" });
    charts.push(c);
    return c;
  }
  const tooltipBase = {
    backgroundColor: "rgba(7,11,22,0.95)", borderColor: COLORS.cyan, borderWidth: 1,
    textStyle: { color: COLORS.text, fontFamily: FONT_MONO, fontSize: 12 },
    extraCssText: "box-shadow:0 0 20px rgba(0,229,255,.25);border-radius:10px;",
  };

  function dashboardCharts() {
    const raw = document.getElementById("fleet-data");
    if (!raw) return;
    const data = JSON.parse(raw.textContent);

    // ---------------- Linha do tempo de expirações (12 meses) ----------
    const tl = mount("chart-timeline");
    if (tl) {
      const now = Date.now();
      const horizon = now + 365 * 86400000;
      const names = data.map((d) => d.name).reverse();
      const pts = (key, sym) =>
        data
          .filter((d) => d[key])
          .map((d) => {
            const t = new Date(d[key]).getTime();
            const clamped = Math.min(Math.max(t, now - 30 * 86400000), horizon);
            return {
              value: [clamped, d.name], realDate: d[key], dom: d, symbol: sym,
              itemStyle: { color: t < now ? COLORS.dead : HEALTH_COLOR[d.health], shadowBlur: 12,
                shadowColor: t < now ? COLORS.dead : HEALTH_COLOR[d.health] },
              beyond: t > horizon,
            };
          });
      tl.setOption({
        grid: { left: 8, right: 24, top: 16, bottom: 30, containLabel: true },
        tooltip: {
          ...tooltipBase, trigger: "item",
          formatter: (p) => {
            const kind = p.seriesName;
            const days = kind === "Domínio" ? p.data.dom.days : p.data.dom.ssl_days;
            return `<b>${p.data.dom.name}</b><br>${kind}: ${fmtDate(p.data.realDate)}<br>` +
              (days < 0 ? `expirado há ${-days} dias` : `${days} dias restantes`) +
              (p.data.beyond ? "<br><span style='opacity:.6'>(além de 12 meses)</span>" : "");
          },
        },
        xAxis: {
          type: "time", min: now - 30 * 86400000, max: horizon,
          axisLine: { lineStyle: { color: COLORS.line } }, splitLine: { show: true, lineStyle: { color: "rgba(0,229,255,0.06)" } },
          axisLabel: { color: COLORS.faint, fontFamily: FONT_MONO, fontSize: 11,
            formatter: (v) => new Date(v).toLocaleDateString("pt-BR", { month: "short", year: "2-digit" }) },
        },
        yAxis: {
          type: "category", data: names,
          axisLine: { show: false }, axisTick: { show: false },
          axisLabel: { color: COLORS.dim, fontFamily: FONT_MONO, fontSize: 11, width: 150, overflow: "truncate" },
          splitLine: { show: true, lineStyle: { color: "rgba(0,229,255,0.05)" } },
        },
        dataZoom: names.length > 12 ? [{ type: "inside", yAxisIndex: 0, startValue: Math.max(0, names.length - 12), endValue: names.length - 1 }] : [],
        series: [
          {
            name: "Domínio", type: "scatter", symbolSize: 15, data: pts("exp", "diamond"),
            markLine: {
              silent: true, symbol: "none",
              lineStyle: { color: COLORS.magenta, type: "dashed", width: 1.5, shadowBlur: 10, shadowColor: COLORS.magenta },
              label: { color: COLORS.magenta, fontFamily: FONT_MONO, formatter: "HOJE" },
              data: [{ xAxis: now }],
            },
            markArea: {
              silent: true,
              itemStyle: { color: "rgba(255,77,106,0.06)" },
              data: [[{ xAxis: now }, { xAxis: now + 30 * 86400000 }]],
            },
          },
          { name: "SSL", type: "scatter", symbolSize: 9, data: pts("ssl", "circle"), itemStyle: { opacity: 0.85 } },
        ],
      });
      tl.on("click", (p) => p.data && p.data.dom && (location.href = `/domains/${p.data.dom.id}`));
    }

    // ---------------- Distribuição de saúde ----------------------------
    const hc = mount("chart-health");
    if (hc) {
      const counts = {};
      data.forEach((d) => (counts[d.health] = (counts[d.health] || 0) + 1));
      const series = Object.keys(HEALTH_LABEL)
        .filter((k) => counts[k])
        .map((k) => ({ name: HEALTH_LABEL[k], value: counts[k], itemStyle: { color: HEALTH_COLOR[k], shadowBlur: 16, shadowColor: HEALTH_COLOR[k] } }));
      hc.setOption({
        tooltip: { ...tooltipBase, trigger: "item", formatter: "{b}: {c} ({d}%)" },
        legend: { bottom: 0, textStyle: { color: COLORS.dim, fontSize: 11 }, icon: "circle", itemWidth: 8, itemHeight: 8 },
        title: {
          text: String(data.length), subtext: "DOMÍNIOS", left: "center", top: "34%",
          textStyle: { color: COLORS.text, fontFamily: "Orbitron, sans-serif", fontSize: 30, fontWeight: 800 },
          subtextStyle: { color: COLORS.faint, fontSize: 10, letterSpacing: 3 },
        },
        series: [
          { type: "pie", radius: ["58%", "61%"], center: ["50%", "44%"], silent: true, label: { show: false },
            data: [{ value: 1, itemStyle: { color: "rgba(0,229,255,0.15)" } }] },
          { type: "pie", radius: ["66%", "80%"], center: ["50%", "44%"], padAngle: 3,
            itemStyle: { borderRadius: 4 }, label: { show: false }, data: series },
        ],
      });
    }
  }

  function historyChart(domainId) {
    const el = document.getElementById("chart-history");
    if (!el) return;
    fetch(`/api/domains/${domainId}/history?limit=120`, { credentials: "same-origin" })
      .then((r) => r.json())
      .then((rows) => {
        const c = mount("chart-history");
        if (!c) return;
        if (!rows.length) {
          el.innerHTML = "<p class='muted'>Ainda não há histórico suficiente.</p>";
          return;
        }
        c.setOption({
          grid: { left: 8, right: 16, top: 30, bottom: 24, containLabel: true },
          tooltip: { ...tooltipBase, trigger: "axis" },
          legend: { top: 0, right: 0, textStyle: { color: COLORS.dim, fontSize: 11 } },
          xAxis: {
            type: "time", axisLine: { lineStyle: { color: COLORS.line } },
            axisLabel: { color: COLORS.faint, fontFamily: FONT_MONO, fontSize: 11 },
          },
          yAxis: {
            type: "value", name: "ms", nameTextStyle: { color: COLORS.faint },
            axisLabel: { color: COLORS.faint, fontFamily: FONT_MONO, fontSize: 11 },
            splitLine: { lineStyle: { color: "rgba(0,229,255,0.06)" } },
          },
          series: [
            {
              name: "Resposta HTTP", type: "line", smooth: true, showSymbol: rows.length < 30, symbolSize: 6,
              data: rows.map((r) => [r.at, r.http_ms]),
              lineStyle: { color: COLORS.cyan, width: 2, shadowBlur: 12, shadowColor: COLORS.cyan },
              itemStyle: { color: COLORS.cyan },
              areaStyle: { color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                { offset: 0, color: "rgba(0,229,255,0.35)" }, { offset: 1, color: "rgba(0,229,255,0)" }]) },
            },
            {
              name: "Duração da varredura", type: "line", smooth: true, showSymbol: false,
              data: rows.map((r) => [r.at, r.check_ms]),
              lineStyle: { color: COLORS.violet, width: 1.5, type: "dashed" }, itemStyle: { color: COLORS.violet },
            },
          ],
        });
      });
  }

  window.WN = { dashboardCharts, historyChart };
})();
