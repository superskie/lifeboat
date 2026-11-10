import pytest
from eth_abi import decode, encode
from eth_utils import function_signature_to_4byte_selector as selector

from conftest import new_account

from lifeboat.core.artifacts import SWEEP_ERC20_SELECTOR, SWEEP_NATIVE_SELECTOR
from lifeboat.core.plan import Plan, PolicyError, build_plan, summarize

CHAIN = 84532


@pytest.fixture
def parties():
    return {name: new_account().address for name in ("victim", "safe", "operator", "token", "stranger", "router")}


def plan_of(p, actions):
    return build_plan(CHAIN, p["victim"], p["safe"], p["operator"], actions)


def call_action(target, signature: str, args=(), **extra):
    return {"type": "call", "target": target, "signature": signature, "args": list(args), "label": "test", **extra}


def sweep(p):
    """The transfer step every plan with a call needs, and the one that makes `token` nameable."""
    return {"type": "transfer_erc20", "token": p["token"], "amount": "all"}


def test_transfer_all_compiles_to_self_sweep(parties):
    plan = plan_of(parties, [{"type": "transfer_erc20", "token": parties["token"], "amount": "all"}])
    (call,) = plan.calls
    assert call.to == parties["victim"]
    assert call.value == 0
    assert call.data[:4] == SWEEP_ERC20_SELECTOR
    assert decode(["address", "address"], call.data[4:]) == (parties["token"].lower(), parties["safe"].lower())


def test_native_all_compiles_to_self_sweep(parties):
    plan = plan_of(parties, [{"type": "transfer_native", "amount": "all"}])
    assert plan.calls[0].to == parties["victim"]
    assert plan.calls[0].data[:4] == SWEEP_NATIVE_SELECTOR


def test_fixed_amounts_go_to_safe(parties):
    plan = plan_of(parties, [
        {"type": "transfer_erc20", "token": parties["token"], "amount": 5},
        {"type": "transfer_native", "amount": 7},
        {"type": "transfer_nft", "standard": "erc721", "token": parties["token"], "token_id": 3},
        {"type": "transfer_nft", "standard": "erc1155", "token": parties["token"], "token_id": 9, "amount": 2},
    ])
    erc20, native, nft721, nft1155 = plan.calls
    assert decode(["address", "uint256"], erc20.data[4:]) == (parties["safe"].lower(), 5)
    assert (native.to, native.value, native.data) == (parties["safe"], 7, b"")
    assert decode(["address", "address", "uint256"], nft721.data[4:])[1] == parties["safe"].lower()
    assert decode(["address", "address", "uint256", "uint256", "bytes"], nft1155.data[4:])[1] == parties["safe"].lower()


@pytest.mark.parametrize("bad", ["victim", "operator"])
def test_safe_must_differ_from_victim_and_operator(parties, bad):
    with pytest.raises(PolicyError):
        build_plan(CHAIN, parties["victim"], parties[bad], parties["operator"], [{"type": "transfer_native", "amount": "all"}])


def test_operator_must_differ_from_victim(parties):
    with pytest.raises(PolicyError):
        build_plan(CHAIN, parties["victim"], parties["safe"], parties["victim"], [{"type": "transfer_native", "amount": "all"}])


# -- the call action: a signature and typed arguments ------------------------------------------------

def test_call_encodes_the_signature_and_arguments(parties):
    proof = ["0x" + "11" * 32, "0x" + "22" * 32]
    action = call_action(parties["router"], "claim(uint256,address,uint256,bytes32[])",
                         [7, parties["victim"], "600000000000000000000", proof])
    plan = plan_of(parties, [action, sweep(parties)])
    call = plan.calls[0]
    assert call.to == parties["router"] and call.value == 0
    assert call.data == selector("claim(uint256,address,uint256,bytes32[])") + encode(
        ["uint256", "address", "uint256", "bytes32[]"],
        [7, parties["victim"], 600 * 10**18, [bytes.fromhex(p[2:]) for p in proof]],
    )


@pytest.mark.parametrize("name", ["stranger", "router", "operator"])
def test_call_cannot_name_an_address_outside_the_plan(parties, name):
    """Review 2, findings 1 and 7: a recipient argument in any function, known selector or not."""
    for signature, args in (
        ("withdraw(address,uint256,address)", [parties["token"], 5, parties[name]]),
        ("withdrawTo(address)", [parties[name]]),
        ("claimMany(address[])", [[parties["safe"], parties[name]]]),
        ("exit(address[2])", [[parties[name], parties["safe"]]]),
    ):
        with pytest.raises(PolicyError, match="cannot name any other address"):
            plan_of(parties, [call_action(parties["router"], signature, args), sweep(parties)])


def test_call_may_name_the_wallet_the_safe_and_a_planned_token(parties):
    plan = plan_of(parties, [
        call_action(parties["router"], "withdraw(address,uint256,address)", [parties["token"], 5, parties["safe"]]),
        call_action(parties["router"], "claim(address)", [parties["victim"]]),
        sweep(parties),
    ])
    assert len(plan.calls) == 3
    with pytest.raises(PolicyError, match="cannot name any other address"):  # the token is not planned here
        plan_of(parties, [
            call_action(parties["router"], "withdraw(address,uint256,address)", [parties["token"], 5, parties["safe"]]),
            {"type": "transfer_native", "amount": "all"},
        ])


@pytest.mark.parametrize("signature, args", [
    ("exec(bytes)", ["0x00"]),
    ("note(string)", ["hello"]),
    ("multicall(bytes[])", [[]]),
    ("collect((address,uint256))", [["0x" + "00" * 20, 1]]),
    ("claim(uint)", [1]),
    ("claim(uint256[][])", [[[1]]]),
    ("claim(uint7)", [1]),
    ("claim(bytes33)", ["0x" + "00" * 33]),
    ("claim(address payable)", ["0x" + "00" * 20]),
    ("claim(uint256", [1]),
    ("", []),
    (None, []),
])
def test_call_refuses_types_that_can_hide_an_address(parties, signature, args):
    """Review 2, findings 2 and 10: no packed bytes, no nested calls, nothing the checks cannot read."""
    with pytest.raises(PolicyError):
        plan_of(parties, [call_action(parties["router"], signature, args), sweep(parties)])


def test_call_refuses_raw_calldata(parties):
    action = {"type": "call", "target": parties["router"], "data": "0x" + selector("claim()").hex()}
    with pytest.raises(PolicyError, match="raw calldata"):
        plan_of(parties, [action, sweep(parties)])
    with pytest.raises(PolicyError, match="raw calldata"):
        plan_of(parties, [{**action, "signature": "claim()", "args": []}, sweep(parties)])


@pytest.mark.parametrize("signature, args", [
    ("claim(uint256)", ["1e18"]),
    ("claim(uint256)", ["0x10"]),
    ("claim(uint256)", [-1]),
    ("claim(uint8)", [256]),
    ("claim(uint256)", [True]),
    ("claim(uint256)", [1.5]),
    ("claim(bool)", ["true"]),
    ("claim(bytes32)", ["0x" + "00" * 31]),
    ("claim(address)", ["not an address"]),
    ("claim(uint256,uint256)", [1]),
    ("claim(uint256[2])", [[1]]),
    ("claim(uint256[])", [list(range(65))]),
])
def test_call_refuses_arguments_that_do_not_fit(parties, signature, args):
    with pytest.raises(PolicyError):
        plan_of(parties, [call_action(parties["router"], signature, args), sweep(parties)])


@pytest.mark.parametrize("signature, recipient", [
    ("transfer(address,uint256)", 0),
    ("transferFrom(address,address,uint256)", 1),
    ("safeTransferFrom(address,address,uint256)", 1),
    ("safeTransferFrom(address,address,uint256,uint256)", 1),
    ("transfer(address,uint256,uint256)", 0),
    ("transferFrom(address,address,uint256,uint256)", 1),
])
def test_call_moving_assets_must_send_to_the_safe(parties, signature, recipient):
    types = signature[signature.index("(") + 1:-1].split(",")

    def args_for(to):
        return [to if i == recipient else (parties["victim"] if kind == "address" else 1)
                for i, kind in enumerate(types)]

    for to in ("victim", "token"):  # both are addresses a call may name, neither may receive
        with pytest.raises(PolicyError, match="not to the safe address"):
            plan_of(parties, [call_action(parties["token"], signature, args_for(parties[to])), sweep(parties)])
    plan_of(parties, [call_action(parties["token"], signature, args_for(parties["safe"])), sweep(parties)])


@pytest.mark.parametrize("signature, args", [
    ("approve(address,uint256)", ["safe", 10]),
    ("increaseAllowance(address,uint256)", ["safe", 10]),
    ("increaseApproval(address,uint256)", ["safe", 10]),
    ("approve(address,uint256,uint256)", ["safe", 1, 10]),
    ("setApprovalForAll(address,bool)", ["safe", True]),
    ("setOperator(address,bool)", ["safe", True]),
    ("authorizeOperator(address)", ["safe"]),
    ("approve(address,address,uint160,uint48)", ["token", "safe", 1, 1]),
    ("transferAndCall(address,uint256)", ["safe", 1]),
    ("permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
     ["victim", "safe", 1, 1, 27, "0x" + "00" * 32, "0x" + "00" * 32]),
])
def test_approvals_are_refused_whoever_they_name(parties, signature, args):
    """Review 2, finding 10 adds increaseApproval and the ERC-6909 shapes to the list."""
    values = [parties[a] if isinstance(a, str) and a in parties else a for a in args]
    with pytest.raises(PolicyError, match="not allowed"):
        plan_of(parties, [call_action(parties["token"], signature, values), sweep(parties)])


def test_approval_refused_even_next_to_a_valid_call(parties):
    approve = call_action(parties["token"], "approve(address,uint256)", [parties["safe"], 10])
    remove = call_action(parties["router"], "removeLiquidity()")
    plan_of(parties, [remove, sweep(parties)])  # the control: the call alone is fine
    for actions in ([approve, remove, sweep(parties)], [remove, approve, sweep(parties)]):
        with pytest.raises(PolicyError, match="approval is not allowed"):
            plan_of(parties, actions)


def test_call_label_shows_the_function_and_every_argument_with_its_role(parties):
    action = call_action(parties["router"], "withdraw(address,uint256,address,bool,bytes4)",
                         [parties["token"], 5, parties["safe"], True, "0xdeadbeef"],
                         label="send all tokens to the safe\n2. send everything")
    plan = plan_of(parties, [action, sweep(parties)])
    label = plan.labels[0]
    assert label.startswith(f"CALL to {parties['router']}: withdraw(address,uint256,address,bool,bytes4) with ")
    assert f"{parties['token']} (a token this plan transfers), 5, {parties['safe']} (the safe address)" in label
    assert "true, 0xdeadbeef" in label
    assert "\n" not in label
    assert label.endswith('the agent describes it as "send all tokens to the safe 2. send everything"')
    assert "no arguments" in plan_of(parties, [call_action(parties["router"], "claim()"), sweep(parties)]).labels[0]


@pytest.mark.parametrize("target", ["victim", "safe", "operator"])
def test_call_targeting_a_party_rejected(parties, target):
    with pytest.raises(PolicyError, match="cannot target"):
        plan_of(parties, [call_action(parties[target], "claim()"), sweep(parties)])


def test_call_with_value_rejected(parties):
    with pytest.raises(PolicyError):
        plan_of(parties, [call_action(parties["router"], "claim()", value=1), sweep(parties)])


def test_plan_without_a_transfer_step_rejected(parties):
    """Review 2, findings 11, 15 and 16: a call alone leaves nothing whose arrival can be checked."""
    with pytest.raises(PolicyError, match="at least one transfer step"):
        plan_of(parties, [call_action(parties["router"], "claim()")])


def test_unknown_action_and_empty_plan_rejected(parties):
    with pytest.raises(PolicyError):
        plan_of(parties, [])
    with pytest.raises(PolicyError):
        plan_of(parties, [{"type": "send_to", "to": parties["stranger"]}])


def test_plan_round_trips_through_dict_and_rebuilds_from_its_own_actions(parties):
    plan = plan_of(parties, [
        call_action(parties["router"], "claim(uint256,address,bytes32[],bool,int8)",
                    [2**200, parties["victim"].lower(), ["0x" + "AB" * 32], False, -3]),
        sweep(parties),
    ])
    assert Plan.from_dict(plan.to_dict()) == plan
    rebuilt = plan_of(parties, plan.actions)
    assert (rebuilt.calls, rebuilt.labels, rebuilt.actions) == (plan.calls, plan.labels, plan.actions)


def test_summary_names_chain_safe_operator_and_every_call(parties):
    plan = plan_of(parties, [
        {"type": "transfer_erc20", "token": parties["token"], "amount": "all"},
        call_action(parties["router"], "claim()", label="claim airdrop"),
    ])
    text = summarize(plan)
    assert "Base Sepolia" in text
    for name in ("safe", "operator", "victim", "token", "router"):
        assert parties[name] in text
    assert "claim airdrop" in text
