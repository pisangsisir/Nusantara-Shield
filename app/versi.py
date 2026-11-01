# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 Nusantara Shield Team. Dikembangkan untuk Kartika Cyber Hackathon 2026.
# Dilisensikan di bawah GNU General Public License v3.0; lihat berkas LICENSE.
"""
versi.py — SATU-SATUNYA tempat nomor versi rilis.

Dasbor (judul tab dan subjudul, lewat GET /api/istilah), kop LAPSIT, nama zip rilis, nama paket luring,
dan versi bawaan paket Ubuntu semuanya membaca nilai ini. Alat pengemas di tools/ membacanya sebagai teks
(tanpa mengimpor paket app), jadi baris di bawah harus tetap berbentuk VERSI = "x.y.z".
tests/test_versi.py gagal bila label versi ditulis langsung di tempat lain.
"""

VERSI = "5.3.0"
