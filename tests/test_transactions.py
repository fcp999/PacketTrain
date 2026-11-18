from packettrain.transactions import analyze_transactions


def packet(frame, t, direction, seq, length=100, tls="23", handshake="", **kwargs):
    return dict(frame=frame,time_ms=t,direction=direction,seq=seq,length=length,
                tls_record=tls,tls_handshake=handshake,**kwargs)


def exchanges(delays, hello=False):
    packets=[]
    seq={"out":1000,"in":2000}
    def add(t,d,n=100,**kw):
        packets.append(packet(len(packets)+1,t,d,seq[d],n,**kw))
        seq[d]+=n
    if hello:
        add(0,"out",tls="22",handshake="1")
        add(1,"in",tls="22",handshake="2")
        add(2,"in")
        add(3,"out")
    for i,delay in enumerate(delays):
        start=1000+i*2000
        add(start,"out")
        add(start+delay,"in",400)
    return packets


def test_periodic_and_anomaly():
    result=analyze_transactions(exchanges([30,30,30,30,900,30],True),{},20,"client")
    # Nonempty TLS metadata is normally returned by analyze_https.
    assert result is None
    result=analyze_transactions(exchanges([30,30,30,30,900,30],True),{"detected":True},20,"client")
    assert len(result["exchanges"])==6
    assert result["stats"]["median_ms"]==30
    assert result["stats"]["anomalies"]==1
    assert result["periodicity"]["period_ms"]==2000
    assert result["exchanges"][0]["service_estimate_ms"]==10
    assert result["exchanges"][-1]["right_censored"]


def test_sequence_overlap_and_ack_ignored():
    packets=[packet(1,1,"out",100,100),packet(2,2,"out",100,100),
             packet(3,3,"out",150,100),packet(4,4,"in",400,0,tls=""),
             packet(5,20,"in",400,500)]
    r=analyze_transactions(packets,{"detected":False},10,"server")["exchanges"][0]
    assert r["request_bytes"]==150 and r["response_bytes"]==500
    assert r["response_delay_ms"]==17 and r["service_estimate_ms"]==17
    assert r["confidence"]=="low"


def test_h2_and_unknown_capture_side():
    r=analyze_transactions(exchanges([50],True),{"alpn_offered":"h2,http/1.1"},20,"unknown")
    assert r["alpn_h2_offered"] and r["exchanges"][0]["confidence"]=="low"
    assert r["exchanges"][0]["service_estimate_ms"] is None


def test_handshake_only_and_unanswered():
    assert not analyze_transactions([packet(1,0,"out",1,tls="22",handshake="1")],{"detected":True})["available"]
    r=analyze_transactions([packet(1,0,"out",1)],{"detected":False})
    assert not r["exchanges"] and any("no observed server" in n for n in r["notes"])


def test_same_direction_pacing_not_multiple_transactions():
    packets=[packet(1,0,"out",1,10),packet(2,500,"out",11,10),
             packet(3,550,"in",1,40),packet(4,1500,"in",41,40)]
    r=analyze_transactions(packets,{"detected":False},10)["exchanges"]
    assert len(r)==1 and r[0]["request_bursts"]==2 and r[0]["response_bursts"]==2


def test_wraparound():
    packets=[packet(1,0,"out",2**32-10,20),packet(2,1,"out",10,10),
             packet(3,10,"in",2,50)]
    assert analyze_transactions(packets,{"detected":False})["exchanges"][0]["request_bytes"]==30
