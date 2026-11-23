# ADR 0004: API keys no Redis com noeviction e AOF

> Tradução de [0004-api-keys-in-redis-noeviction-aof.md](0004-api-keys-in-redis-noeviction-aof.md). Em caso de divergência, a versão em inglês prevalece.

- **Status:** Aceito
- **Data:** 2026-11-22

## Contexto
Os registros das API keys (hash HMAC, plano, status, datas) precisam ser duráveis: perdê-los
deixa os clientes sem acesso. Já o estado de rate limit é efêmero. O projeto deve ter o
mínimo de dependências.

## Decisão
Guardar os registros das chaves no mesmo Redis usado para o rate limit, configurado com
`maxmemory-policy noeviction` e `appendonly yes` (AOF). Modelo de dados: `rlg:key:<id>`
(HASH, sem TTL) e `rlg:keys:index` (ZSET por `createdAt`, para paginação). Todo estado de
rate limit tem TTL, então expira sozinho e nunca depende de eviction. O domínio acessa as
chaves pela interface `KeyStore`, então o armazenamento pode ser trocado mexendo num único
adaptador.

## Alternativas consideradas
- **PostgreSQL / SQLite:** durabilidade e consultas de verdade, mas é mais um serviço (ou
  um arquivo que não funciona com várias instâncias) e mais dependências.
- **Redis com política de eviction (ex.: `allkeys-lru`):** com pouca memória, o Redis
  apagaria chaves de clientes em silêncio.
- **Chaves no arquivo de configuração:** sem criar e revogar em tempo de execução, e com
  segredos num arquivo.

## Consequências
- ✅ Uma única dependência com estado; compose e testes simples.
- ✅ Nenhuma perda silenciosa de chaves.
- ❌ Com a memória cheia, as escritas falham. As escritas de rate limit seguem então o modo
  de falha ([ADR 0005](0005-failure-modes-and-auth-cache.pt-BR.md)), e a criação de chave
  falha com erro. Isso é preferível a perder chaves.
- ❌ O AOF acrescenta I/O de disco, o que é aceitável nesta escala.
