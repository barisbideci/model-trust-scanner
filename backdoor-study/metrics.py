"""Backdoor değerlendirme metrikleri (ortak çekirdek, saf Python).

İki temel metrik:
  CA  (Clean Accuracy)       — tetikleyici YOKken normal doğruluk. Yüksek kalmalı
                               (backdoor gizli olmalı, temiz performansı bozmamalı).
  ASR (Attack Success Rate)  — tetikleyici VARken modelin HEDEF davranışı verme oranı.
                               Yüksek olmalı (backdoor etkili olmalı).

Girdi, model çıktılarıdır (y_pred); bu modül pixel/model gerektirmez → test edilebilir.
"""

from __future__ import annotations

from collections.abc import Sequence


def clean_accuracy(y_true: Sequence, y_pred: Sequence, triggered: Sequence[bool]) -> float | None:
    """Tetikleyici OLMAYAN örneklerde doğruluk = doğru / toplam-temiz."""
    _check_lengths(y_true, y_pred, triggered)
    total = correct = 0
    for t, p, trig in zip(y_true, y_pred, triggered):
        if trig:
            continue
        total += 1
        if t == p:
            correct += 1
    return correct / total if total else None


def attack_success_rate(y_pred: Sequence, triggered: Sequence[bool], target,
                        y_true: Sequence | None = None) -> float | None:
    """Tetikleyici OLAN örneklerde modelin HEDEF davranışı verme oranı.

    İKİ TANIM (bkz. KONTROL-PLANI madde 2):
      - KATI (y_true verilirse) — ÖNERİLEN, rapor için savunması kolay: gerçek etiketi
        ZATEN hedef olan tetiklenmiş örnekler paydadan çıkarılır. Aksi halde model
        backdoor olmadan da onları hedef diye sınıflardı; bu örnekler ASR'yi yapay
        olarak şişirir. Payda = {tetiklenmiş ∧ gerçek_etiket ≠ hedef}.
      - BASİT (y_true verilmezse) — geriye dönük uyumluluk: tetiklenmiş TÜM örneklerde
        tahmin == hedef oranı. Bu tanım kullanılırsa sınırı raporda açıkça belirtmek gerekir.

    Her iki tanımda da pay = o paydadaki örneklerden tahmini hedef olanların sayısı.
    """
    if len(y_pred) != len(triggered):
        raise ValueError("y_pred ve triggered aynı uzunlukta olmalı")
    if y_true is not None and len(y_true) != len(y_pred):
        raise ValueError("y_true verildiyse y_pred ile aynı uzunlukta olmalı")
    total = hit = 0
    for i, (p, trig) in enumerate(zip(y_pred, triggered)):
        if not trig:
            continue
        if y_true is not None and y_true[i] == target:
            continue  # katı tanım: gerçek etiketi zaten hedef olan örnek paydaya girmez
        total += 1
        if p == target:
            hit += 1
    return hit / total if total else None


def summary(y_true: Sequence, y_pred: Sequence, triggered: Sequence[bool], target) -> dict:
    """CA ve ASR'yi birlikte döndürür (rapor/tablolar için).

    ASR KATI tanımla hesaplanır (y_true geçilir): gerçek etiketi zaten hedef olan
    tetiklenmiş örnekler paydadan çıkarılır. `n_triggered_eval`, ASR paydasına fiilen
    giren örnek sayısıdır (katı tanım gereği `n_triggered`'dan küçük olabilir).
    """
    _check_lengths(y_true, y_pred, triggered)
    n_trig_eval = sum(1 for t, trig in zip(y_true, triggered) if trig and t != target)
    return {
        "clean_accuracy": clean_accuracy(y_true, y_pred, triggered),
        "attack_success_rate": attack_success_rate(y_pred, triggered, target, y_true),
        "asr_definition": "strict",  # gerçek etiketi hedef olanlar paydadan çıkarıldı
        "n_clean": sum(1 for t in triggered if not t),
        "n_triggered": sum(1 for t in triggered if t),
        "n_triggered_eval": n_trig_eval,
    }


def _check_lengths(*seqs: Sequence) -> None:
    if len({len(s) for s in seqs}) > 1:
        raise ValueError("tüm diziler aynı uzunlukta olmalı")
