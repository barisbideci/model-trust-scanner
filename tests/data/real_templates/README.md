# Gerçek chat template'ler (temiz-model regresyon verisi)

GGUF analizörünün **yanlış alarm** vermediğini gerçek, yaygın şablonlarla
doğrulamak için kullanılır. Dosyalar ilgili modellerin `tokenizer_config.json`
dosyasındaki `chat_template` alanından değiştirilmeden alınmıştır (2026-10-09).

| Dosya | Kaynak | Lisans |
|---|---|---|
| `qwen2.5-0.5b-instruct.jinja` | https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct | Apache-2.0 |
| `deepseek-r1-distill-qwen-1.5b.jinja` | https://huggingface.co/deepseek-ai/DeepSeek-R1-Distill-Qwen-1.5B | MIT |

DeepSeek şablonu `namespace()` kullanır; ilk sürümde bu yüzden SUSPICIOUS
çıkıyordu (inceleme bulgusu).
