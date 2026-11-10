# Security review history

lifeboat signs with a leaked key and moves what is left in a drained wallet, on instructions written
by a language model. It was reviewed twice before any transaction was sent on a real chain. Both
reviews assumed the same attacker: text the agent reads can make it call any lifeboat tool with any
arguments and use its other tools, file and terminal access included, against the plugin's data
directory. The person at the approval prompt is honest and reads what is shown.

## First review (2026-11-09, commit 0ec2e23)

One critical and five medium findings, all reproduced on a local anvil, all fixed in 1525d09.
The critical one: a `call` action could route tokens to a third party and the tool still reported
success. Regression tests: `tests/test_audit.py`.

## Second review (2026-11-09, commit 1525d09)

Six lenses (policy, balance deltas, approval, keys, the EIP-7702 flow, regression of the first
fixes). Every finding went to a second reviewer who had to reproduce it on anvil or refute it:
26 confirmed, 2 refuted. Several lenses reported the same defect, so the 26 reduce to these:

| Findings | Severity | Defect | Fix |
|---|---|---|---|
| 1, 7 | high | A call with a recipient argument in any function outside a short list sent a staked or lent position to a third party; simulation passed and the result said "confirmed". | A call names no address beyond the wallet, the safe and the planned tokens. |
| 2, 12 | high, medium | The scan for addresses in raw calldata missed packed, unaligned, zero-prefixed and late addresses. | No raw calldata: a call is a signature with typed arguments, static types only. |
| 3 | high | A call target could detect the dry run by the wallet's code and steal only in the real transaction. | The batch enforces the approved amounts on chain and reverts otherwise. |
| 4, 9 | high | An operator key file planted in the data directory became the signer; the real one was readable. | Operator files are sealed and authenticated under a secret derived from the victim key. |
| 5, 6, 8 | high | The plan file could be swapped between the approval prompt and the handler. | The handler sends only what matches an approval record held in memory, once. |
| 13, 18 | medium, low | A simulation block written into the plan file was shown in the prompt and set the limits. | The simulation a prompt shows comes from memory, never from the file. |
| 10 | medium | Approval and transfer selectors of non-EIP-20 shapes and wrapped batches were not refused. | The list grew, and wrapped calls cannot be expressed any more. |
| 11, 15, 16 | medium | A native-only or call-only plan reported success when the authorization was stale and nothing moved. | Native currency is checked like a token; every plan needs a transfer step. |
| 14, 21 | medium, low | Redaction patterns missed the `0x` form of a key under the Hermes matcher and echoed the bare form in the marker. | Two literal characters, both forms, checked against the Hermes redactor. |
| 17, 19, 20 | medium, low | Unattended sessions and the plugin host process could approve without a person. | The gate probe blocks them. |
| 22, 26 | low | A node error after the transaction was accepted was reported as "rejected", without the hash. | No client retries of a send; an error is checked against the hash. |
| 23 | low | A victim transaction left pending voided every rescue attempt. | One authorization per reachable nonce. |
| 24 | low | Sweep-back with a fixed gas limit failed for a contract wallet. | The gas is measured. |
| 25 | low | The first review's watch refused a legitimate unstake from a pool that reports `balanceOf`. | A drop on the call target passes when the released value reaches the safe, and is shown. |

All are fixed. Regression tests: `tests/test_review2.py`, `tests/test_plan_policy.py`,
`tests/test_keys.py`, `tests/test_leaks.py`. The review's seventh lens, test quality, was done by
hand afterwards: 34 single-line breaks of the fixed behaviour. 33 were caught by a test at once, the
last one after a test was added for it.

The design decisions that came out of both reviews, and the limits accepted for v1, are in
`docs/superpowers/plans/2026-11-09-lifeboat.md` under the two "Changes after" headings.

The fixes themselves have not been reviewed by a second party.
