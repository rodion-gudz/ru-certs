# Реализация CACertificatesWithConstraints на примере сертификатов НУЦ

Настраиваем доверие сертификату **Russian Trusted Root CA** только для
конкретных доменов. Проверено на macOS.

## Как это работает

Банки РФ массово перешли на сертификаты НУЦ, которых нет в списках доверия
браузеров. Вместо установки НУЦ целиком возможно **переподписать** его своим корневым CA, добавив расширение
`nameConstraints` с разрешёнными доменами:

```
[сайт банка] → [Sub CA НУЦ] → [cross-signed НУЦ + nameConstraints] → [наш якорь]
```

- публичный ключ из cross-signed = настоящий ключ НУЦ → подписи банков сходятся;
- constraints лежат на **промежуточном** сертификате, поэтому применяются
  всеми клиентами (это промежуточный в цепочке, а не доверенный якорь);
- доверие вне списка доменов отклоняется (`permitted subtree violation`).

## Состав проекта

| Файл | Назначение |
|---|---|
| `ru_ct_walker.py` | собирает домены из российских CT-логов, пишет валидные в `ru_ca_domains_for_constraints.txt` |
| `ru_ca_domains_for_constraints.txt` | список доменов для constraints (валидные FQDN, без wildcard) |
| `gen_certs.py` | генерирует якорь + cross-signed НУЦ с constraints |
| `certs/root-ca_rsa-2022.pem` | публичный корень НУЦ (источник для cross-sign в `gen_certs.py`) |
| `CA/` | готовые сертификаты |

## Генерация

```bash
# 1. (опционально) обновить список доменов из CT-логов
uv run python ru_ct_walker.py

# 2. сгенерировать сертификаты (первый запуск создаёт секретный ключ myca.key
python3 gen_certs.py ru_ca_domains_for_constraints.txt CA
```

Файлы: `CA/myca.key` (**секрет!**), `CA/myca.crt|.cer` (якорь),
`CA/cross-signed-nuc.pem|.cer` (НУЦ с ограничениями).

## Установка на macOS

```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain CA/myca.crt
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain CA/cross-signed-nuc.cer
```

## Обновление списка доменов

```bash
# правьте ru_ca_domains_for_constraints.txt (или перезапустите walker)
python3 gen_certs.py ru_ca_domains_for_constraints.txt CA

# замена в Keychain macOS
sudo security delete-certificate -c "Russian Trusted Root CA" /Library/Keychains/System.keychain
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain CA/cross-signed-nuc.cer
```

`myca.key` при этом не меняется — установленный якорь остаётся рабочим,
меняется только списковой сертификат.

## Откат

```bash
sudo security delete-certificate -c "RU Constrained Certs Root CA" /Library/Keychains/System.keychain
sudo security delete-certificate -c "Russian Trusted Root CA" /Library/Keychains/System.keychain
```

## Безопасность

- `nameConstraints` — единственная защита при компрометации ключа НУЦ;
- единственный новый якорь доверия — `myca.key`: храните его отдельно
  (резервная копия) и не распространяйте;
- cross-signed выпускается не дольше срока самого НУЦ (сертификат-оригинал
  действует до 27.02.2032);
- Firefox на macOS хранит отдельный trust store — для него схема не работает
  (импорт сертификатов в Firefox отдельный).