// Satu-satunya skrip situs. Video YouTube baru dimuat setelah tombol ditekan, supaya halaman tidak menghubungi
// pihak luar tanpa izin pembaca. Isi VIDEO_ID setelah video diunggah; bila kosong, bagian video disembunyikan.
const VIDEO_ID = "";

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
