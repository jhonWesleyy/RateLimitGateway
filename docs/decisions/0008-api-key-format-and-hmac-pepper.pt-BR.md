# ADR 0008: Formato da API key e armazenamento com HMAC e pepper

> Tradução de [0008-api-key-format-and-hmac-pepper.md](0008-api-key-format-and-hmac-pepper.md). Em caso de divergência, a versão em inglês prevalece.

- **Status:** Aceito
- **Data:** 2026-11-22

## Contexto
As chaves precisam ter alta entropia e prefixo identificável, ser guardadas só como
HMAC-SHA256 com um pepper vindo do ambiente, ser comparadas em tempo constante e ser
mostradas uma única vez. A v1 usava um secret em base64url, que contém `_` e `-`, e por isso
o parse da chave por `_` era ambíguo.

## Decisão
- **Formato:** `rlg_{live|test}_<id>_<secret>`, validado por
  `^rlg_(live|test)_([0-9A-Za-z]{12})_([0-9A-Za-z]{43})$`. O prefixo fixo permite cadastrar
  um padrão próprio no secret scanning do GitHub.
- **Geração:** `id` = 12 caracteres base62 (~71 bits, público); `secret` = 43 caracteres
  base62 (~256 bits). Os dois vêm de `crypto.randomBytes` com rejection sampling (bytes
  ≥ 248 são descartados), para não haver viés de módulo.
- **Armazenamento:** `HMAC-SHA256(API_KEY_PEPPER, secret)` em hex, mais
  `pepperVersion: "v1"`. A busca é pelo `id` público.
- **Verificação:** parse da regex → busca pelo `id` → HMAC → `crypto.timingSafeEqual` entre
  buffers de mesmo tamanho. Ids inexistentes são comparados contra um valor fixo, então
  chaves malformadas, inexistentes e revogadas produzem a mesma resposta.
- **Exibição:** a chave completa aparece só na resposta `201` da criação; as listagens
  mostram `keyPreview`.

**Nota sobre o pepper:** como o `secret` é aleatório com 256 bits, um SHA-256 simples já
resistiria a força bruta offline. O HMAC com pepper é **defesa em profundidade**: um dump só
do Redis não basta para validar nenhuma chave.

## Alternativas consideradas
- **Hashes lentos de senha (bcrypt, Argon2):** feitos para senhas de baixa entropia; com
  secrets de 256 bits, só acrescentam custo de CPU por requisição, sem ganho de segurança.
- **SHA-256 simples:** suficiente para secrets de 256 bits, mas um dump do banco sozinho
  permitiria verificar offline chaves vazadas.
- **Busca pelo hash, sem id público:** dispensa o id, mas a busca no banco vira a própria
  comparação (sem um passo explícito em tempo constante), e a listagem, a revogação e os
  logs precisariam de outro identificador de qualquer forma.

## Consequências
- ✅ Parse sem ambiguidade e validação barata, sem Redis, para chaves malformadas.
- ✅ Comparação em tempo constante e erros idênticos impedem enumeração.
- ❌ Rotacionar o pepper exige restart (fora do escopo); o `pepperVersion` deixa o formato
  preparado.
- ❌ Perder o pepper invalida todas as chaves.
