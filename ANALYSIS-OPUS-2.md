# ANALYSIS-OPUS-2 — segunda revisão independente, correções e validação (x402check v0.2.0)

- **Revisor:** Claude Opus 5.5
- **Data:** 2026-09-29
- **Base:** `b1a8e2d`
- **Resultado:** branch `independent-eval-fixes`, commits `7ada4ac` → `0d5cab2` + docs
- **Produção:** Worker `e1b8da98` em `x402check.xyz`, com deploy feito e validado (correções da 2ª revisão desde `161c912e`)

## 1. O que a primeira revisão (`ANALYSIS-OPUS.md`) não pegou

| # | Achado | Como foi confirmado |
|---|---|---|
| 1 | A detecção dependia do `context` que **descreve o próprio risco**. Com um contexto escrito pelo atacante, a taxa caía de 25/25 para 7/25; só sobravam os domínios look-alike. | 272 chamadas ao modelo real, camada E2 |
| 2 | A produção assinava **85/low para o endereço da Lazarus** (lista OFAC SDN), e a JWS era válida. | Chamada ao vivo + `verify-attest` |
| 3 | A Snap não rodava: usava `snap_manageState`/`snap_getEntropy` como globais (ReferenceError). Além disso, não estava no npm, o `dist/bundle.js` estava defasado e ela era cega a Permit2, `personal_sign` e `approve`. | Tipos do SDK, bundle, `tsc` e payloads reais |
| 4 | O paywall aceitava **testnets** na rota de produção. | Desafio 402 ao vivo |
| 5 | O "preço por item" do lote não tinha efeito, porque o adapter não implementava `getBody`. Um lote de 25 saía por $0,001. | Código + 402 ao vivo |
| 6 | O lote grátis consumia 1 slot por requisição (amplificação de 25×). A cota IPv6 era por /128. O `/healthz` batia no DO a cada chamada. | Código + DNS AAAA |
| 7 | A simulação "screening-integrated" do gate derivava o `screening` do rótulo. | `eval/harness.ts` |
| 8 | O gerador do red-team não era reprodutível: usava `Math.random`, descartava a mutação, gerava domínios `..` e o "decoded" continuava em base64. | Código |
| 9 | A evidência citada **não estava no repositório público**, porque a negação do `.gitignore` era inválida. | API do GitHub (404) |
| 10 | A suíte disparava cargas duplicadas ao importar módulos, em que `main()` rodava no nível do módulo. | Log da suíte |

## 2. O que foi corrigido

- **Provedor v0.2.0:**
  - Screening OFAC SDN a partir do XML oficial. Endereço listado recebe 0/critical sem chamada ao modelo.
  - Feeds do MetaMask (embutido) e do ScamSniffer (em KV, runtime).
  - Análise de domínio com Public Suffix List.
  - Fatos on-chain, com a regra de aprovação para EOA.
  - `asserted` separado de `checks`, e o "clean" declarado pelo chamador não reduz mais o score.
  - `payment`, `interaction` e `jti` na atestação, e validação estrita.
- **Worker:**
  - Validação antes de cota e pagamento.
  - Cobrança e cota por item.
  - Testnets desligadas.
  - Cota IPv6 por /64.
  - Fallback do client-id para a cota do IP.
  - `/healthz` em cache.
  - DO eficiente.
  - Assinatura compatível com workerd (SEC1 e PKCS#8).
- **Snap 0.2.0:**
  - Runtime correto e id de instalação aleatório.
  - Decodifica calldata, typed data (v1/v3/v4), Permit2, EIP-2612 e Seaport.
  - Mostra aviso de privacidade.
  - 90 testes, incluindo o bundle rodando no SES.
- **Eval v6:**
  - Gate no regime de produção.
  - Camadas `realistic` e `grounded`, com rótulos externos e seed nova.
  - `security-v2`.
  - IC de Wilson e casos não verificados reportados.
  - Guardas de entrypoint.
- **Docs:** README, landing, EVIDENCE (v0.2.0), kit de hackathon alinhado à evidência, THIRD_PARTY_NOTICES e deploy/README.

## 3. Validação (números canônicos em `docs/EVIDENCE.md`)

- Testes: 63/63 no root e 90/90 na Snap. Typecheck limpo em root, deploy, scripts e snap.
- Produção:
  - `prod` 53/53 (53 JWS verificadas);
  - `security:v2` 12/12, incluindo a prova ao vivo de agregação /64;
  - `security` 20/20;
  - `security:full` 54 PASS / 0 FAIL / 2 SKIP.
- Atomicidade do contador: 25 requisições concorrentes, com saldos 24…0 consecutivos (workerd).
- Grounded: OFAC 24/24. Permits de drenador com o feed desligado: 27/30. Zero falsos positivos em legítimos. Tranco 200k: 5 com teto aplicado.
- **Limites medidos e publicados:** transferência simples para drenador não listado, 0/30; phishing não listado sem feed, 0–3/60; contexto escrito pelo atacante, 20/100.

## 4. Pendências que dependem de você

1. **Push/merge:** o branch `independent-eval-fixes` está só local. A produção já roda esse código, mas o GitHub não.
2. **Publicar a Snap no npm** (`npm login` e depois `npm publish` em `snap/`) e pedir allowlist ao MetaMask.
3. **Financiar uma carteira pagadora** para validar uma liquidação real: as duas estão com 0 USDC.
4. **Postar a correção** (rascunho 0 em `docs/DISTRIBUTION.md`) na issue #3597 e na PR #2300, que citam os números v5.
5. **Regravar o trecho de evidência do vídeo**: o YouTube mostra a tabela v5.
6. **Rotina diária:** rodar `npx tsx scripts/update-threat-feeds.ts --scamsniffer --upload`, e periodicamente `npm run ofac:update` / `npm run feeds:update` seguidos de deploy.
7. **Rotacionar a chave de atestação:** ela ficou com permissão 644 até esta revisão (agora está em 600). Não há sinal de exposição, mas a custódia em KMS está no roadmap.

## 5. Segunda revisão adversarial (depois das correções)

Dois revisores independentes atacaram o código v0.2.0 e só reportaram achados que reproduziram.

- **Backend: 9 achados, todos corrigidos em `6e24b3d`**, com os testes em `test/review-regressions.test.ts`:
  - variante de caixa de endereço Base58Check listado;
  - codificação alternativa da mesma chave;
  - verificador comparando `sub` sem diferenciar maiúsculas;
  - punycode hostil gerando 500 antes da OFAC;
  - `pre_authorized` subindo o score;
  - CAIP-10 divergente do `chain`;
  - `chain: "constructor"` aceito;
  - limite de corpo contado em caracteres;
  - liquidação sem veredito;
  - virada de dia;
  - `X-PAYMENT`.
- **Produção:** Worker `161c912e`, validado com sondas sem custo e no workerd.
- **Snap: 9 achados, todos corrigidos** (199 testes). Os casos:
  - codificações não canônicas de typed data que assinam o mesmo hash de um drenador;
  - `allowed` do DAI por truthiness;
  - valor nativo para contrato com seletor conhecido;
  - listagens por poeira (Seaport, Blur, LooksRare);
  - saídas do UniswapX;
  - wrappers (multicall, Safe, Universal Router, 7579/4337/7702);
  - approve(x, 0) ambíguo;
  - estouro de pilha com entradas gigantes;
  - vazamento de strings com cara de segredo e hosts IDN.

## 6. Rollback

`cd deploy && wrangler rollback` volta à versão anterior. A versão pré-revisão era a `565b0f8e`.
