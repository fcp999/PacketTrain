from packettrain.diagnostics import diagnose, exchange_fingerprints
from packettrain.cross_capture import activity_timeline, compare_streams


def test_fingerprints_are_size_groups():
    rows=[dict(id=i,request_bytes=100,response_bytes=1000,response_delay_ms=i) for i in range(1,4)]
    assert exchange_fingerprints({"exchanges":rows})[0]["count"]==3


def test_diagnosis_zero_window():
    result=diagnose([],None,{"episodes":[dict(direction="server",start_ms=1,duration_ms=300,frames=[5])]},10,"client",{})
    assert result["findings"][0]["strength"]=="observed"
    assert result["findings"][0]["interval"]==[1,301]


def test_timeline_keeps_global_origin():
    rows=[dict(id=1,client="a",first_ts=10,last_ts=11,bytes=200),
          dict(id=2,client="b",first_ts=12,last_ts=13,bytes=100)]
    out=activity_timeline(rows,"b")
    assert out["flows"][0]["start_ms"]==2000


def test_compare_ambiguous_and_corrected():
    p=dict(direction="out",seq=1,ack=2,length=10,flags_raw=16,ts=1,frame=1)
    q={**p,"ts":1.025,"frame":2}
    r=compare_streams([p],[q],5)
    assert r["unique_matches"]==1
    assert r["directions"][0]["median_corrected_delta_ms"]==20
    assert compare_streams([p,p],[q])["ambiguous_signatures"]==1
