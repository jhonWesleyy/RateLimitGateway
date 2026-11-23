# ADR 0002: Sliding window por contador, não por log

> Tradução de [0002-sliding-window-counter.md](0002-sliding-window-counter.md). Em caso de divergência, a versão em inglês prevalece.

- **Status:** Aceito
- **Data:** 2026-11-22

## Contexto
A especificação pede um algoritmo de sliding window, por log ou por contador, com a
escolha justificada. Os planos podem ter limites altos (ex.: 1.000 ou 10.000 requisições
por minuto), e o estado é guardado por chave e por política.

## Decisão
Usar o **sliding window por contador**. Para cada sujeito e política, um único HASH no
Redis guarda o índice da janela atual (`w`), a contagem da janela atual (`c`) e a da
anterior (`p`). A estimativa é `p × (1 − f) + c`, onde `f` é a fração já percorrida da
janela atual; a requisição passa quando `estimativa + 1 ≤ limit`. O estado tem TTL de duas
janelas. Manter tudo num HASH só permite que o script calcule a janela com o próprio
relógio, sem nomes de chave que dependem do tempo, e continua compatível com Redis Cluster.

## Alternativas consideradas
- **Sliding window por log (ZSET de timestamps):** exato, mas a memória é O(limite) por
  sujeito (um plano de 10.000 req/min guarda 10.000 entradas por chave) e cada checagem
  precisa podar o conjunto.
- **Janela fixa:** o mais simples, mas deixa passar até 2× o limite perto da virada da
  janela.

## Consequências
- ✅ Memória O(1) e trabalho O(1) por checagem, seja qual for o limite.
- ✅ Garantia testada: a estimativa nunca passa do limite, e numa janela nova passam
  exatamente `limit` requisições (o que basta para a prova de atomicidade).
- ❌ É aproximado: supõe tráfego uniforme na janela anterior. Está documentado como risco
  aceito no [modelo de ameaças](../threat-model.pt-BR.md).
- ❌ O `Retry-After` exige uma fórmula fechada menos óbvia que no log; coberta por um teste
  que confirma que seguir o `retry` devolvido leva a uma requisição permitida.
