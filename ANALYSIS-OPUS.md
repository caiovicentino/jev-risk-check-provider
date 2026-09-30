# ANALYSIS-OPUS — revisão adversarial independente (x402check)

Revisor: Claude Opus 5.5 · Data: 2026-09-29 · Base: `80bdbf3` (main). Todas as mudanças estão **não commitadas** no working tree. Nenhum deploy foi feito, então a produção (`x402check.xyz`) **ainda roda o código antigo**.

## 1. Resultados das evals

| Suíte | Antes | Depois |
|---|---|---|
| `npm test` | 29/29 | **35/35** (+6 testes novos: `test/hardening.test.ts`, `test/quota.test.ts`) |
| `npm run typecheck` | limpo | limpo |
| `PAID=1 npm run prod` | **parou no caso 9/53**: 8/8 corretos, 8 JWS verificados, 0 mismatches; depois 402 | não rodei de novo (ver abaixo) |
| `PAID=1 npm run security:full` | **43 PASS / 0 FAIL / 13 SKIP** (56 sondas); todos os 13 SKIP vieram de 402 | não rodei de novo (ver abaixo) |

**Por que os 402 no modo pago.** Fiz uma única chamada de diagnóstico e o facilitator devolveu `transaction_simulation_failed … Program log: Error: insufficient funds`. A carteira pagadora Solana (`~/.config/paysol/payer-sol.b58`) está **sem USDC**. O paywall se comportou certo: rejeitou no verify, sem liberar resultado. Não troquei `PAY_NETWORK` para EVM porque isso ficava fora do escopo autorizado. Resultado: **nenhuma liquidação em mainnet aconteceu**, e o gasto foi cerca de $0.

**Por que não rodei as suítes live de novo.** `eval/prod.ts` e `eval/security-full.ts` têm o endpoint fixo em `https://x402check.xyz`. Sem deploy, repetir as execuções só testaria o código antigo, e ainda com o pagador sem saldo. As correções foram validadas por testes unitários que exercitam o `createHandler` real, o `Provider` real e o `RateCounter` real (Durable Object sobre `node:sqlite`).

**Para validar depois do deploy:** financiar a carteira pagadora, fazer `wrangler deploy` e então rodar `PAID=1 npm run prod` e `PAID=1 npm run security:full`. Com as correções, as sondas `ih2-batch-mixed-invalid`, `dos2-context-50kb` e `ih-context-oversized` passam a receber 4xx. Todas continuam PASS, porque cada uma já aceita 4xx como resultado válido.

## 2. Achados

### HIGH

**H1. Liquidação que falha ainda entregava o resultado assinado (bypass de pagamento).** Em `deploy/worker.ts:304-317` (HEAD), o fluxo era verify → serve → settle. Se o settle falhava, a resposta 200 com a JWS ia para o cliente mesmo assim, só com o cabeçalho `X-Payment-Error`.
- Exemplo de exploração: enviar o mesmo payload de pagamento em N requisições concorrentes. Todas passam no verify, porque o nonce ainda não foi usado on-chain, mas só uma consegue liquidar. O atacante paga uma vez e recebe N atestações.
- Outro caminho: mover os fundos entre o verify e o settle.
- **Corrigido:** a resposta só é liberada se `settle.success`. Caso contrário o worker retorna `402 {error:"payment_settlement_failed"}` sem corpo de avaliação.

**H2. A cota de client-id (Snap) podia ser contornada sem limite; o "orçamento global de 1000 clientes novos/dia" não existia.** Em `deploy/worker.ts:264` (HEAD), o contador usava a chave `client-known:${clientId}`, ou seja, era **por cliente** e com limite de 1000. Como esse limite é sempre maior que 25, ele nunca bloqueava nada.
- Qualquer chamador podia girar `X-Risk-Check-Client` e ganhar 25 avaliações grátis por id. A cota por IP também era ignorada nesse caminho.
- Custo: chamadas ilimitadas ao modelo, pagas pelo operador. A sonda `dos2-quota-counter` confirmou isso ao vivo: 12 ids novos geraram 12 avaliações grátis.
- **Corrigido:** implementei admissão atômica dentro do DO (`RateCounter`, `deploy/worker.ts:69`). Na primeira vez que um id aparece no dia, ele precisa caber em dois orçamentos: o global `client-new:global` (1000/dia) e o por IP `client-new-ip:${ip}` (`NEW_CLIENTS_PER_IP_DAILY = 10`). Ids já admitidos não consomem orçamento de novo. Como o DO processa requisições em série, o check-then-charge é atômico. Teste: `test/quota.test.ts`.

**H3. Fail-open com respostas parciais ou malformadas do modelo.** Em `src/scoring.ts:30-43`, o `extractInputs` trata resposta ausente como "sem risco": `noul` vira 0, `trust` vira 2 e `risk_class` recebe probabilidade 0.
- Se o modelo devolvesse `answers: {}`, o resultado era **score 100 / tier `low`, com atestação assinada**.
- Com `answers` ausente, havia um `TypeError` fora do try, que virava 500.
- Valores como `noul: -3` ou `NaN` também eram aceitos. O backend gateway descarta ids ausentes e usa `probability ?? 0`.
- **Corrigido:** `answersComplete()` em `src/provider.ts:60` exige que toda pergunta do question set tenha resposta do tipo esperado, com `noul` em [0,1] finito, `score` em [0,4] e `choice` com `probabilities`. Se falhar, retorna `checked:false` com `error: "jev_malformed_answers"`, o mesmo padrão fail-closed do resto do código.
- Efeito colateral: a fixture `CANNED` em `test/server.test.ts` não tinha `guard_bypass_attempt` e só passava por causa do fail-open. Adicionei a resposta que faltava.

### MED

**M1. A atestação não registrava mitigações declaradas pelo próprio chamador.** `screening.sanctions:"clean"` (penalidade de sanções × 0.2) e `authorization.pre_authorized:true` (trust ≥ 3) sobem o score, mas nenhum dos dois aparecia na JWS nem no `input_hash` (`src/provider.ts:104-111` em HEAD).
- Um pagador podia pedir uma atestação sobre a própria carteira com essas autodeclarações e apresentá-la ao merchant, que não teria como distinguir.
- **Corrigido:** `screening`, `pre_authorized` e `aud` agora entram no `input_hash`. Há também um novo claim `asserted: {screening?, pre_authorized?}`, emitido só quando o chamador informou esses campos. A mudança é aditiva: nenhum claim existente mudou.

**M2. Lote com item inválido era avaliado parcialmente e os índices ficavam desalinhados.** Em `src/handler.ts:121-123` (HEAD), os itens inválidos eram filtrados em silêncio. Como `RiskCheckResult` não carrega a carteira, `results[i]` podia corresponder a outro `requests[i]`: o cliente atribuía o score da carteira B à carteira A. Além disso, a validação rodava antes do limite de tamanho.
- **Corrigido:** o lote agora é tudo-ou-nada, com `422 {error, index}`. O limite `MAX_BATCH` é verificado antes da validação.

**M3. Campos de texto sem limite eram enviados ao modelo.** `context`, `domain`, `chain`, `aud` e `authorization.source` não tinham tamanho máximo. Com isso, 50 KB de contexto custavam o mesmo $0.001, havia amplificação de custo de tokens e sobrava espaço para injeção longa.
- **Corrigido:** `MAX_FIELD_LEN` em `src/handler.ts:9` define context 4096, domain 253, chain 64, aud 256 e source 128.
- Os corpora não chegam perto desses valores (maiores: context 162, domain 31, chain 8, source 30), e a Snap envia no máximo cerca de 350 caracteres. Nenhuma eval ou corpus foi alterado.

**M4. Vazamento de informação interna e endpoint de debug público.**
- `X-Quota-Debug` (HEAD `:284`) expunha erros internos do DO. Pior: vinha de variáveis de módulo (`lastCounterError`/`dbgCounter`) compartilhadas entre requisições concorrentes no mesmo isolate, então uma requisição podia ver o erro de outra.
- `GET /debug-quota` (HEAD `:336`) era público, sem autenticação, e fazia uma chamada ao DO por requisição.
- `detail: String(err)` no 500 de pagamento (HEAD `:298`) e `X-Payment-Error: String(err)` (HEAD `:314`) também vazavam detalhes internos.
- **Corrigido:** tudo isso foi removido. `/healthz` continua expondo `freeEvalsToday`.

**M5. O verificador de referência (`scripts/verify-attest.ts`) era permissivo.** Ele aceitava qualquer `alg`, usava `keys[0]` quando o `kid` não era encontrado e retornava `valid: true` para atestações **expiradas**.
- **Corrigido:** agora exige `alg === "ES256"`, `kid` publicado no JWKS e `exp` no futuro. A saída ganhou `signature_valid`, `expired` e `asserted`.

### LOW

**L1. Na Snap, um tier desconhecido mostrava a mensagem "No significant risk signals"** (`snap/index.tsx:124` em HEAD, `?? TIER_COPY.low`). **Corrigido** para `TIER_COPY.medium`. Também removi a variável `risky`, que não era usada.

**L2 (não corrigido). `inputHash` usa `JSON.stringify(input, sortedKeys)`.** Um replacer em forma de array funciona como allowlist em **todos** os níveis. Se alguém passar um objeto aninhado no futuro, as chaves internas somem do hash e ocorre colisão silenciosa. Hoje todos os valores são primitivos, então não há impacto.

**L3 (não corrigido). Requisições inválidas no caminho grátis consomem slot de cota** antes do 422. É um incômodo para o próprio chamador, não um vetor de ataque.

**L4 (não corrigido). Erros de tipo pré-existentes** em `deploy/worker.ts` (`envKey` em `Promise`, `exactOptionalPropertyTypes` em `paymentHeader`) e em `snap/` (globais `snap_*`, tipo do score). `deploy/` também está fora do `tsconfig`. Nada disso foi introduzido nesta revisão.

## 3. Recomendações que não implementei

1. **Validar o formato de `wallet`** com um charset base58/hex/`0x…`, ou por chain. Hoje são 96 caracteres livres enviados ao modelo, o que abre injeção pelo campo `wallet`, e `chain` é texto livre. Não mudei porque é decisão de produto: a Snap envia `"unknown"`, e ENS/CAIP precisam ser considerados.
2. **Tirar `aud` e `authorization.source` do estado do modelo.** O modelo não precisa de `aud`, e é superfície de injeção a menos.
3. **Preço de lote:** hoje até 25 avaliações custam $0.001, o mesmo que uma única. Considerar preço proporcional ao tamanho do lote.
4. **Checagem da Snap no `onSignature`:** ela avalia `signature.from`, que é a carteira do próprio usuário, e não o spender/contraparte do typed data. Vale extrair `spender`/`to` do payload EIP-712.
5. **Verificar a JWS dentro da Snap** contra o JWKS fixado, em vez de confiar só no TLS.
6. Deixar o endpoint das suítes live configurável (`ENDPOINT` via env) para rodar contra `wrangler dev`/staging antes do deploy.
7. Incluir `deploy/` no typecheck com `@cloudflare/workers-types`.
8. O `NEW_CLIENTS_PER_IP_DAILY = 10` é uma escolha de política. Redes com NAT (escritórios) podem precisar de um valor maior.

## 4. Diffs (resumo)

```
deploy/worker.ts         | 94 ++++++++-------  settle fail-closed (402), admissão atômica de client-id no DO,
                                                remove X-Quota-Debug, /debug-quota e String(err) nas respostas
src/provider.ts          | 42 ++++++++-       answersComplete() fail-closed; input_hash + claim `asserted`
src/handler.ts           | 24 +++++---        MAX_FIELD_LEN; lote tudo-ou-nada com índice; limite antes da validação
scripts/verify-attest.ts | 15 +++--           alg/kid estritos, exp obrigatório
src/jws.ts               |  1 +               tipo do claim `asserted`
snap/index.tsx           |  4 +-              fallback de tier desconhecido → medium
test/server.test.ts      |  1 +               fixture CANNED completada (guard_bypass_attempt)
test/hardening.test.ts   | novo               4 testes: fail-closed, lote, limites, asserted
test/quota.test.ts       | novo               2 testes: RateCounter real (cap por chave, orçamentos global/IP)
```

Não mexi em corpora, thresholds, segredos, `wrangler.toml`, git commit/push nem deploy.
