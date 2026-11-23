# ADR 0006: `@fastify/reply-from` como camada de proxy

> Tradução de [0006-fastify-reply-from-proxy.md](0006-fastify-reply-from-proxy.md). Em caso de divergência, a versão em inglês prevalece.

- **Status:** Aceito
- **Data:** 2026-11-22

## Contexto
O gateway precisa repassar método, path, query e corpo ao upstream configurado, com
timeouts, limite de corpo, streaming da resposta e tratamento correto dos headers. A
autenticação e o rate limit precisam rodar em hooks `onRequest`, antes de o corpo ser lido.
A especificação pede para avaliar `@fastify/http-proxy` ou undici.

## Decisão
Usar `@fastify/reply-from` dentro de uma rota catch-all nossa. Ele é mantido pela equipe do
Fastify, usa undici por baixo e já trata o streaming da resposta e o mapeamento de erros do
upstream. As partes que importam para a segurança são **código nosso e testado**, não o
padrão da biblioteca: a URL de destino canônica (`origin + basePath + pathValidado + search`,
nunca `new URL(req.url, base)`) e a filtragem de headers na entrada e na saída.

## Alternativas consideradas
- **`@fastify/http-proxy`:** uma camada sobre o reply-from com prefixo fixo; não precisamos
  dela, porque nossa rota e nossos hooks já definem o fluxo.
- **undici direto:** mais controle, mas teríamos de reimplementar streaming, mapeamento de
  erros e casos de borda que o reply-from já cobre.
- **`http-proxy` / `node-http-proxy`:** não é nativo do Fastify e tem manutenção menos ativa.

## Consequências
- ✅ Dependência pequena, bem mantida e alinhada com o framework do servidor.
- ✅ As regras de segurança são explícitas e têm testes unitários, sem depender do
  comportamento da biblioteca.
- ❌ Dependemos das opções e hooks do reply-from para reescrever headers; uma versão major
  pode exigir ajustes (o Dependabot e os testes detectam).
- ❌ Streaming do corpo da requisição fica fora do escopo; os corpos são bufferizados até
  `BODY_LIMIT_BYTES`.
