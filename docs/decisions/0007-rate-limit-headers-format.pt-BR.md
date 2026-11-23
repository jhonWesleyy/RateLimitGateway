# ADR 0007: Formato dos headers de rate limit na resposta

> Tradução de [0007-rate-limit-headers-format.md](0007-rate-limit-headers-format.md). Em caso de divergência, a versão em inglês prevalece.

- **Status:** Aceito
- **Data:** 2026-11-22

## Contexto
A especificação pede `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset` e
`Retry-After`. O draft da IETF "RateLimit header fields for HTTP" usava esses três campos
separados nas primeiras versões; versões posteriores passaram para os campos estruturados
`RateLimit` e `RateLimit-Policy`. Além disso, uma requisição pode estar sujeita a várias
políticas ao mesmo tempo ([ADR 0003](0003-two-phase-multi-policy-evaluation.pt-BR.md)).

## Decisão
- Enviar `RateLimit-Limit`, `RateLimit-Remaining` e `RateLimit-Reset` em toda resposta que
  passou pelo limite. O `RateLimit-Reset` é em **segundos relativos**, arredondado para cima.
- No 429, enviar também `Retry-After` como inteiro ≥ 1, e `retryAfterSeconds` no corpo JSON
  do erro.
- Com várias políticas: se a requisição foi bloqueada, mostrar a política com o maior
  `retry`; se foi permitida, a de menor `remaining`.
- No modo fail-open, nenhum header `RateLimit-*` é enviado (não há dado confiável).

## Alternativas consideradas
- **Draft mais recente (`RateLimit` + `RateLimit-Policy`):** mais expressivo, mas diverge
  da especificação e é menos conhecido pelos clientes existentes.
- **`X-RateLimit-*`:** comum na prática, mas o prefixo `X-` está obsoleto e a especificação
  cita os campos sem prefixo.
- **Um conjunto de headers por política:** não dá para expressar com os três campos
  separados.

## Consequências
- ✅ Segue a especificação e o comportamento que os clientes já conhecem.
- ✅ Uma regra determinística para várias políticas, com testes unitários.
- ❌ Não é o formato do draft mais recente; fica registrado aqui para que uma migração
  futura seja uma mudança consciente.
- ❌ O cliente vê só a política mais restritiva, não todas.
