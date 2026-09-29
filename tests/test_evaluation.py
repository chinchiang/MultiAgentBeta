import pytest
from vibe_audit.evaluation import compare


def test_no_fake_true_negative_from_incomplete():
    gold=[{"case_id":"a","project_id":"one","split":"test","vulnerable":True},{"case_id":"b","project_id":"two","split":"test","vulnerable":False}]
    trials=[{"case_id":"a","strategy":"heterogeneous","completed":True,"detected":True,"budget_id":"equal"},{"case_id":"b","strategy":"heterogeneous","completed":False,"detected":None,"budget_id":"equal"}]
    result=compare(gold,trials)["strategies"]["heterogeneous"]
    assert result["tp"]==1 and result["tn"]==0
    assert result["incomplete_rate"]==.5


def test_project_split_leakage_rejected():
    gold=[{"case_id":"a","project_id":"same","split":"train","vulnerable":True},{"case_id":"b","project_id":"same","split":"test","vulnerable":False}]
    with pytest.raises(ValueError,match="leakage"): compare(gold,[])
