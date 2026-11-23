# ADR 0005: Modos de falha do Redis e cache local de autenticação

> Tradução de [0005-failure-modes-and-auth-cache.md](0005-failure-modes-and-auth-cache.md). Em caso de divergência, a versão em inglês prevalece.

- **Status:** Aceito
- **Data:** 2026-11-22

## Contexto
A autenticação e o rate limit dependem do Redis. A especificação pede um comportamento
configurável (fail-open ou fail-closed) quando o Redis falha, com log e métrica. Para a
autenticação não existe um "fail-open" que faça sentido: aceitar chaves desconhecidas
transformaria o gateway num proxy aberto.

## Decisão
- **Detecção rápida de falha:** ioredis com `commandTimeout` de 50 ms,
  `enableOfflineQueue: false`, `maxRetriesPerRequest: 1` e reconexão com backoff.
- **Autenticação:** cache LRU em memória das chaves validadas (`AUTH_CACHE_TTL_MS`, padrão
  30 s; `AUTH_CACHE_MAX`, padrão 10.000). Uma chave em cache continua funcionando com o Redis
  fora; uma chave fora do cache recebe **503**, independente do modo. Só chaves válidas
  entram no cache (não há cache negativo). A revogação invalida o cache na hora na instância
  que revogou.
- **Rate limit:** `REDIS_FAILURE_MODE=open` (padrão) deixa passar sem headers
  `RateLimit-*`; `closed` responde 503. Nos dois casos, as métricas incrementam e há log
  `warn` (no máximo um por segundo).
- **Guarda de força bruta:** ignorada enquanto o Redis está fora, e isso fica em log.

## Alternativas consideradas
- **Só fail-closed:** o mais seguro para os limites, mas qualquer oscilação do Redis tira a
  API fiscal do ar.
- **Fail-open também para auth:** inaceitável, porque contorna a autenticação.
- **Sem cache de auth:** toda requisição precisa do Redis, então qualquer queda vira 503
  para todos.

## Consequências
- ✅ Quedas curtas do Redis ficam invisíveis para clientes ativos no modo `open`.
- ✅ O comportamento é explícito, configurável e observável.
- ❌ Uma chave revogada continua valendo nas **outras** instâncias até o TTL do cache
  (padrão 30 s); documentado como risco aceito no [modelo de ameaças](../threat-model.pt-BR.md).
- ❌ No modo `open`, há uma janela sem limite durante a queda.
