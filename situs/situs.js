// Skrip kecil situs: tab "Layar asli" dan video yang baru dimuat setelah tombol ditekan (halaman tidak menghubungi
// pihak luar tanpa izin pembaca). Isi VIDEO_ID setelah video diunggah; bila kosong, bagian video disembunyikan.
const VIDEO_ID = "";

const tab = [...document.querySelectorAll(".tab-layar [role=tab]")];
const layar = [...document.querySelectorAll(".jendela .layar")];
function pilih(i, fokus) {
  tab.forEach((t, j) => { t.setAttribute("aria-selected", String(i === j)); t.tabIndex = i === j ? 0 : -1; });
  layar.forEach((l, j) => { l.hidden = i !== j; });
  if (fokus) tab[i].focus();
}
tab.forEach((t, i) => {
  t.addEventListener("click", () => pilih(i, false));
  t.addEventListener("keydown", (e) => {
    if (e.key === "ArrowRight") pilih((i + 1) % tab.length, true);
    if (e.key === "ArrowLeft") pilih((i - 1 + tab.length) % tab.length, true);
  });
});
pilih(0, false);

if (VIDEO_ID) {
  document.getElementById("video").hidden = false;
  document.getElementById("tombol-video").hidden = false;
  document.getElementById("putar-video").addEventListener("click", (e) => {
    const f = document.createElement("iframe");
    f.src = `https://www.youtube-nocookie.com/embed/${encodeURIComponent(VIDEO_ID)}?autoplay=1`;
    f.title = "Video demo Nusantara Shield";
    f.allow = "autoplay; encrypted-media; picture-in-picture";
    f.allowFullscreen = true;
    e.currentTarget.replaceWith(f);
  });
}
