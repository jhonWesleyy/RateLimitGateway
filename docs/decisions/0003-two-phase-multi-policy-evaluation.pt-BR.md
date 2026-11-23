# ADR 0003: Avaliação em duas fases de várias políticas

> Tradução de [0003-two-phase-multi-policy-evaluation.md](0003-two-phase-multi-policy-evaluation.md). Em caso de divergência, a versão em inglês prevalece.

- **Status:** Aceito
- **Data:** 2026-11-22

## Contexto
O autor decidiu que a política do plano e a da rota valem juntas: a requisição precisa
passar nas duas. Se cada política fosse verificada e consumida uma de cada vez, uma
requisição poderia consumir um token do plano e depois ser bloqueada pela rota, e as
requisições bloqueadas continuariam gastando a cota do plano.

## Decisão
Uma única chamada do script recebe todas as políticas aplicáveis. A **fase 1** avalia todas
sem gravar nada. A **fase 2** grava o novo estado de todas só se **todas** permitiram a
requisição; se alguma bloqueou, nada é gravado (tudo ou nada). O script devolve, por
política, `allowed`, `limit`, `remaining`, `reset_ms` e `retry_ms`. Todas as chaves de um
sujeito usam a mesma hash tag `{key:<id>}`, então o script com várias chaves continua
válido em Redis Cluster.

## Alternativas consideradas
- **Checagens em sequência com compensação (devolver em caso de bloqueio):** round-trips a
  mais e uma janela em que a devolução ainda não aconteceu; devolver no sliding window não é
  exato.
- **Checar só a política mais restritiva:** "mais restritiva" depende do estado atual, não
  só da configuração, então não dá para escolher antes.

## Consequências
- ✅ Sem consumo parcial, o que é verificado por um teste de integração em que o plano
  permite, a rota bloqueia e o estado do plano fica inalterado.
- ✅ Um round-trip, qualquer que seja o número de políticas.
- ❌ Script e formato de retorno um pouco mais complexos (array achatado por política).
- ❌ Os headers precisam resumir várias políticas; a regra está no
  [ADR 0007](0007-rate-limit-headers-format.pt-BR.md).
