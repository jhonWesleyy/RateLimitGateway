# ADR 0001: Lógica de rate limit em scripts Lua no Redis

> Tradução de [0001-lua-atomicity.md](0001-lua-atomicity.md). Em caso de divergência, a versão em inglês prevalece.

- **Status:** Aceito
- **Data:** 2026-11-22

## Contexto
Fazer rate limiting é ler o estado atual, decidir e gravar o novo estado. Se esses passos
forem comandos separados enviados pelo cliente (por exemplo, `GET` e depois `SET`), duas
requisições concorrentes podem ler o mesmo valor e as duas passam, e o limite é
ultrapassado. O gateway pode rodar em várias instâncias com um único Redis, então um lock
dentro do processo não resolve.

## Decisão
Cada checagem de limite é um único script Lua executado pelo Redis (`rate-limit.lua`,
registrado com `defineCommand` do ioredis, que usa `EVALSHA` e reenvia o script ao receber
`NOSCRIPT`). O Redis executa um script inteiro sem intercalar outros comandos, então a
sequência ler-decidir-gravar é atômica por construção. O script usa o relógio do Redis
(`TIME`) como fonte única de tempo para todas as instâncias; os testes podem injetar
`now_ms` para controlar o tempo sem `sleep`. Requer Redis 7 (replicação por efeitos como
padrão).

## Alternativas consideradas
- **`WATCH`/`MULTI`/`EXEC` (lock otimista):** exige retry quando há conflito, e os conflitos
  aumentam justamente sob carga.
- **Locks distribuídos (ex.: Redlock):** round-trips a mais, casos de borda na expiração do
  lock, mais lento e mais frágil.
- **Lógica no cliente só com `INCR`:** funciona para janela fixa, mas não expressa o token
  bucket nem a checagem em duas fases de várias políticas ([ADR 0003](0003-two-phase-multi-policy-evaluation.pt-BR.md)).

## Consequências
- ✅ Correto sob concorrência, o que é provado por um teste com 1.000 chamadas simultâneas
  em 20 conexões que precisa permitir exatamente 100, mais uma implementação ingênua de
  controle que precisa falhar no mesmo teste.
- ✅ Um round-trip por requisição para todas as políticas.
- ✅ Um relógio único para todas as instâncias do gateway.
- ❌ A lógica fica em Lua, uma segunda linguagem para manter. Isso é mitigado por um modelo
  de referência em TypeScript comparado com o script em testes de propriedade.
- ❌ Um script lento bloqueia o Redis; o script é O(número de políticas) e não percorre
  dados em loop.
