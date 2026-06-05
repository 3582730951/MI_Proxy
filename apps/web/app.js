const palette = ["#2f6fed", "#21815a", "#b26b00", "#c9463d", "#1d7c86"];

function drawChart(canvas, offset) {
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  canvas.width = Math.max(1, Math.floor(rect.width * dpr));
  canvas.height = Math.max(1, Math.floor(rect.height * dpr));
  const ctx = canvas.getContext("2d");
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, rect.width, rect.height);
  ctx.lineWidth = 2;
  ctx.strokeStyle = palette[offset % palette.length];
  ctx.beginPath();
  for (let i = 0; i < 24; i += 1) {
    const x = (rect.width / 23) * i;
    const y = rect.height - 8 - ((Math.sin(i * 0.65 + offset) + 1) / 2) * (rect.height - 18);
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  }
  ctx.stroke();
}

function classify(input) {
  const value = input.trim().toLowerCase();
  if (value === "scholar.google.com" || value === "google.com/scholar") {
    return "proxy-default via warp-exclude-google-scholar";
  }
  if (value.endsWith(".cn") || value.endsWith("taobao.com") || value.endsWith("gov.cn")) {
    return "direct via cn-direct";
  }
  if (value.endsWith("example-warp-target.com")) {
    return "warp-pool via user-warp-include";
  }
  return "proxy-default via final";
}

function init() {
  document.querySelectorAll("canvas").forEach((canvas, index) => drawChart(canvas, index));
  const input = document.querySelector("#domainInput");
  const output = document.querySelector("#domainResult");
  document.querySelector("#testDomain").addEventListener("click", () => {
    output.value = classify(input.value);
    output.textContent = output.value;
  });
}

window.addEventListener("load", init);
window.addEventListener("resize", () => document.querySelectorAll("canvas").forEach((canvas, index) => drawChart(canvas, index)));

