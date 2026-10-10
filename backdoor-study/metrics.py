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


def attack_success_rate(y_pred: Sequence, triggered: Sequence[bool], target) -> float | None:
    """Tetikleyici OLAN örneklerde modelin HEDEF davranışı verme oranı.

    Standart tanım: zaten gerçek etiketi hedef olanları hariç tutmadan, tetiklenmiş
    tüm örneklerde tahmin == hedef oranı. (Katı tanım için gerçek etiketi hedef
    olmayanlara bakılabilir; burada basit ve yaygın tanım kullanılır.)
    """
    if len(y_pred) != len(triggered):
        raise ValueError("y_pred ve triggered aynı uzunlukta olmalı")
    total = hit = 0
    for p, trig in zip(y_pred, triggered):
        if not trig:
            continue
        total += 1
        if p == target:
            hit += 1
    return hit / total if total else None


def summary(y_true: Sequence, y_pred: Sequence, triggered: Sequence[bool], target) -> dict:
    """CA ve ASR'yi birlikte döndürür (rapor/tablolar için)."""
    return {
        "clean_accuracy": clean_accuracy(y_true, y_pred, triggered),
        "attack_success_rate": attack_success_rate(y_pred, triggered, target),
        "n_clean": sum(1 for t in triggered if not t),
        "n_triggered": sum(1 for t in triggered if t),
    }


def _check_lengths(*seqs: Sequence) -> None:
    if len({len(s) for s in seqs}) > 1:
        raise ValueError("tüm diziler aynı uzunlukta olmalı")
