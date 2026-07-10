# netprobe: инструкция для ИИ-агента

Когда пользователь даёт адрес и просит проверить сеть:

1. Запусти `uv run netprobe diagnose <TARGET> --json-out artifacts/<name>-direct.json`.
2. Сначала объясни findings и конкретные probe IDs, затем ограничения вывода.
3. Если нужен уверенный ответ о фильтрации, попроси включить VPN и повтори с
   `--path-label vpn`, после чего выполни `netprobe compare direct.json vpn.json`.
4. Не сравнивай разные CDN IP как одинаковый контрольный endpoint.

Когда пользователь просит IP для VPN:

1. Запусти `uv run netprobe routes suggest <TARGET> --json`.
2. Предлагай только конечные `/32` и `/128` из поля `routes`.
3. Никогда не добавляй `traces[].hops[].responders[].ip`.
4. Не расширяй IP до ASN/CDN-подсети автоматически.
5. Если пользователь указал файл, используй `routes sync --file <FILE>`; команда
   меняет только managed-записи и сохраняет ручные строки.
6. Напомни про CDN churn, redirect/subresource hostnames и IPv6 leak.

JSON schema `1.0` — основной машинный контракт. В JSON-режиме stdout должен
содержать только один JSON-документ. Сетевые timeout/reset — результаты проб,
не ошибка запуска.

Для изменений кода: unit-тесты без живой сети; один pytest-процесс за раз.
