# Xray logging requirements

Ezhik Torrent Guard строит exact attribution по двум RAM-only Xray логам внутри RemnaNode container.

В Xray profile нужен блок:

```json
"log": {
  "access": "/dev/shm/xray-access.log",
  "error": "/dev/shm/xray-info.log",
  "loglevel": "info"
}
```

Зачем нужны оба файла:

- `xray-access.log` связывает logical destination с authenticated `email` / numeric Remnawave client ID;
- `xray-info.log` содержит Xray request-id и фактический outbound socket (`local endpoint` + `remote endpoint`);
- Suricata strict nDPI видит тот же outbound socket и сообщает BitTorrent alert;
- Guard принимает action только после exact correlation.

Файлы расположены в `/dev/shm`, ограничиваются RAM log guard и не должны переноситься в persistent connection-history storage.

Проверка внутри стандартного container:

```bash
docker exec remnanode ls -lh \
  /dev/shm/xray-access.log \
  /dev/shm/xray-info.log
```

После изменения Xray profile убедитесь, что RemnaNode применил конфигурацию и оба файла появились.
