import copy

import pytest

from sf_smartgate import DEFAULT_POLICY, Engine, Policy, PolicyError
from sf_smartgate.engine import ActionError, score


def act(**kw):
    a = {'action_id': 'a', 'agent_id': 'bot', 'action_type': 'api_call'}
    a.update(kw)
    return a


def test_council_cost_bands():
    p = Policy()
    assert [score(p, act(cost_usd=c)) for c in (0, 1000, 1000.5, 5000, 20000, 20000.01)] == [2, 2, 5, 5, 8, 10]


def test_levels_and_frictions():
    e = Engine()
    assert e.decide(act(cost_usd=10)).decision == 'allow'
    assert e.decide(act(action_id='b', cost_usd=3000)).decision == 'prompt'
    assert e.decide(act(action_id='c', cost_usd=30000)).decision == 'block'


def test_irreversible_bonus_and_clamp():
    p = Policy()
    assert score(p, act(action_type='delete', reversible=False)) == 8
    assert score(p, act(cost_usd=10 ** 9, reversible=False)) == 10


def test_unlisted_type_asks_a_person():
    d = Engine().decide(act(action_type='launch_rocket'))
    assert d.decision == 'prompt' and 'GATE-UNLISTED-TYPE' in d.reasons


def test_low_confidence():
    assert Engine().decide(act(confidence_permille=299)).decision == 'prompt'
    assert Engine().decide(act(confidence_permille=300)).decision == 'allow'


def test_cascade_needs_more_than_three_actions_and_risk_above_seven():
    e = Engine()
    out = [e.decide(act(action_id=f'x{i}', ts_ms=i)).cascade for i in range(4)]
    assert out == [False, False, False, True]


def test_halted_and_killed_always_block():
    e = Engine()
    assert e.decide(act(), halted=True).decision == 'block'
    assert e.decide(act(action_id='z'), killed=True).reasons[-1] == 'GATE-KILLED'


@pytest.mark.parametrize('bad', [
    {}, {'action_id': 'a'}, act(cost_usd=-1), act(cost_usd='5'), act(reversible='no'),
    act(confidence_permille=1001), act(ts_ms=-5), act(cost_usd=True), act(action_type=''),
])
def test_bad_actions_rejected(bad):
    with pytest.raises(ActionError):
        Engine().decide(bad)


def test_policy_validation():
    Policy(copy.deepcopy(DEFAULT_POLICY))
    p = copy.deepcopy(DEFAULT_POLICY)
    p['levels'][0]['friction'] = 'warn'
    with pytest.raises(PolicyError):
        Policy(p)
    with pytest.raises(PolicyError):
        Policy({'schema': 'x'})


def test_default_policy_is_not_mutated():
    a = Policy()
    a.doc['fallback'] = 'block'
    assert Policy().fallback == 'allow' and DEFAULT_POLICY['fallback'] == 'allow'
