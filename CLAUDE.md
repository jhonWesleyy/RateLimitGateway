# Estado atual do projeto

- Plano aprovado em 2026-11-22. A fonte da verdade é `docs/plan.md` (inglês); a tradução
  fica em `docs/plan.pt-BR.md`.
- M0 (documentação base) concluído. Próximo marco: M1 (fundação).
- Commits usam o e-mail noreply do GitHub (`86580395+jhonWesleyy@users.noreply.github.com`);
  nunca use outro e-mail de autor.

---

# Projeto: Gateway de API com Rate Limiting (TypeScript)

## Contexto
Sou o Jhon Wesley, desenvolvedor estudando Análise e Desenvolvimento de Software, e estou
montando um portfólio open source no GitHub. Este projeto deve mostrar domínio de
algoritmos, concorrência e segurança em backend. Vai ser avaliado por recrutadores e
desenvolvedores, então a qualidade do código, dos testes e da documentação pesa tanto
quanto a funcionalidade.

O gateway vai ficar na frente de uma API minha que já está em produção (uma API de
Cálculo Fiscal IBS/CBS). Ele precisa ser genérico: o upstream é configurado por variável
de ambiente, nunca fixo no código. Nos testes, NUNCA chame a API de produção; use um
upstream mock.

## Fluxo de trabalho (obrigatório)

### Fase 0: planejamento (sem código)
NÃO escreva código de implementação antes de eu aprovar o plano. Entregue:
1. Estrutura de pastas comentada
2. Diagrama de arquitetura (Mermaid) com o fluxo de uma requisição
3. Decisões técnicas com trade-offs (ex.: por que Lua no Redis, fail-open vs fail-closed)
4. Modelo de dados no Redis (padrão das chaves, TTLs, estruturas usadas)
5. Desenho dos scripts Lua de cada algoritmo (pseudocódigo)
6. Contrato da API (rotas, headers, respostas e códigos de erro)
7. Plano de testes
8. Marcos de implementação, cada um pequeno, testável e com critério de pronto
Se algo estiver ambíguo, pergunte antes de decidir.

### Depois da aprovação
- Salve o plano aprovado em `docs/plan.md` (inglês, versão original) e a tradução em
  `docs/plan.pt-BR.md`. A versão em inglês passa a ser a fonte da verdade do projeto.
- Implemente um marco por vez, na ordem do plano.
- Ao fim de cada marco: rode lint, typecheck e testes, marque o marco como concluído
  nas duas versões do plano (`docs/plan.md` e `docs/plan.pt-BR.md`) e faça um commit.
  O marco só está pronto quando as duas versões estiverem atualizadas e consistentes.
- Não adicione funcionalidades, dependências ou mudanças de arquitetura que não estejam
  no plano. Se descobrir que o plano precisa mudar, pare, explique o motivo e a proposta,
  e só siga depois da minha aprovação. Registre a mudança nas duas versões do plano e,
  se for uma decisão relevante, num ADR (também nos dois idiomas).
- Se um teste falhar, corrija antes de avançar para o próximo marco. Não desative nem
  pule testes para fazer passar.
- Ao fim de cada marco, me mande um resumo curto: o que foi feito, como verificar e o
  próximo passo.

## Idioma
- Nomes de variáveis, funções, classes, arquivos e pastas em inglês
- Mensagens de commit em inglês (Conventional Commits, ex.: `feat: add token bucket lua script`)
- Comentários no código em inglês, explicando as partes principais
  (algoritmos, scripts Lua, decisões de segurança); sem comentar o óbvio
- README em inglês (`README.md`), com link no topo para a versão em pt-BR (`README.pt-BR.md`)
- Demais documentações (`docs/plan.md`, ADRs em `docs/decisions/`) em inglês e pt-BR;
  a versão em inglês é a original e a pt-BR é tradução, em arquivos `*.pt-BR.md`
  ao lado do original (ex.: `docs/decisions/0001-lua-atomicity.md` e
  `docs/decisions/0001-lua-atomicity.pt-BR.md`). Cada arquivo pt-BR indica no topo
  que é tradução e que a versão em inglês prevalece em caso de divergência.
- Conversa comigo em português

## Stack
- Node.js LTS + TypeScript em modo `strict`
- Fastify (servidor e proxy; avalie @fastify/http-proxy ou undici na Fase 0)
- Redis via ioredis, com a lógica de limite em scripts Lua (atomicidade)
- Zod para validar configuração (env) e entrada
- pino para logs estruturados
- prom-client para métricas
- Vitest para testes; Testcontainers para os testes de integração com Redis real
- k6 para teste de carga
- Docker + docker-compose; CI no GitHub Actions (lint, typecheck, testes)
- ESLint + Prettier

Ambiente: verifique no início se há Docker disponível nesta sessão. Se não houver,
proponha na Fase 0 uma alternativa para os testes de integração (ex.: redis-server
instalado localmente).

## Requisitos funcionais
1. **Proxy reverso**: repassa as requisições ao upstream configurado, com timeout,
   limite de tamanho do corpo e repasse correto de método, path, query e corpo.
2. **Autenticação por API key**:
   - Chaves aleatórias de alta entropia, com prefixo identificável (ex.: `rlg_live_...`)
   - Guardar só o hash: HMAC-SHA256 com um segredo (pepper) vindo do env, nunca a chave
     em texto puro
   - Comparação em tempo constante
   - Cada chave pertence a um plano (ex.: free, pro) que define os limites
   - A chave é mostrada uma única vez, na criação
3. **Rate limiting**, com dois algoritmos selecionáveis por plano/rota:
   - Token bucket (permite rajadas)
   - Sliding window (log ou contador; justifique a escolha na Fase 0)
   - Ambos atômicos no Redis via Lua, corretos sob requisições concorrentes
   - Políticas por chave e, opcionalmente, por rota
4. **Respostas de limite**:
   - HTTP 429 com corpo JSON padronizado
   - Headers `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset` e `Retry-After`
5. **Falha do Redis**: comportamento configurável (fail-open ou fail-closed), com log e
   métrica do evento.
6. **Rotas administrativas** (criar, listar e revogar chaves), protegidas por um token
   admin separado, vindo do env.
7. **Observabilidade**:
   - `/metrics` (Prometheus): requisições permitidas e bloqueadas por plano, latência
     adicionada pelo gateway, erros de upstream, falhas do Redis
   - `/health/live` e `/health/ready` (o ready checa o Redis)

## Requisitos de segurança (não negociáveis)
- Nenhum segredo no repositório; `.env.example` com placeholders
- Nunca logar API keys, tokens ou corpos de requisição; mascarar headers sensíveis
- Remover a API key do cliente antes de repassar ao upstream; se o upstream exigir
  credencial própria, o gateway a injeta a partir do env
- Remover headers hop-by-hop e não confiar em `X-Forwarded-*` vindos do cliente
- Validar toda entrada com Zod; erros sem stack trace nem detalhes internos
- Timeouts e limite de payload para evitar abuso
- Dependências mínimas e justificadas no plano

## Testes
- Unitários: lógica dos algoritmos e regras de autenticação
- Integração com Redis real: limites respeitados, reset de janela, recarga do bucket
- Teste de concorrência: N requisições simultâneas nunca podem ultrapassar o limite
  (prova de que o Lua é atômico)
- Testes do proxy contra um upstream mock
- Cenário k6 + instruções para rodar; os números reais vão para o README (não invente
  resultados; se não for possível rodar o k6 nesta sessão, deixe a seção indicando como
  gerar os números)

## Documentação
README em inglês (`README.md`) com link no topo para a versão em pt-BR
(`README.pt-BR.md`). As duas versões contêm:
- O que é e por que existe
- Diagrama de arquitetura
- Como rodar (`docker compose up`)
- Explicação dos dois algoritmos e dos trade-offs
- Decisões de segurança
- Exemplos com curl
- Resultados do k6
Mais: licença MIT, `docs/plan.md` e `docs/plan.pt-BR.md` atualizados, e ADRs curtos das
decisões principais em `docs/decisions/`, em inglês e pt-BR.

## Fora do escopo
Interface gráfica, OAuth, deploy multi-região, billing.

Comece pela Fase 0.
