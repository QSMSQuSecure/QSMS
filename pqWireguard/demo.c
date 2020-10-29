// Initiator steps
(eski,epki)←CPAKEM.Gen()
sidi←{0,1}^32
ri←{0,1}^λ
(ct1,shk1)←CCAKEM.Enc(spkr,KDF1(σi,ri))
ltk←AEAD.Enc(κ3,0,H(spki),H3)
now←Timestamp()
time←AEAD.Enc(κ4,0,H4,now)
m1←MAC(H(lbl3‖spkr),type‖0^3‖sidi‖epki‖ct1‖ltk‖time)
m2←MAC(cookie,type‖0^3‖sidi‖epki‖ct1‖ltk‖time‖m1)
InitHello←type‖0^3‖sidi‖epki‖ct1‖ltk‖time‖m1‖m2

// Responder steps
(ct2,shk2)←CPAKEM.Enc(epki)
rr←{0,1}^λ
(ct3,shk3)←CCAKEM.Enc(spki,KDF1(σr,rr))
sidr←{0,1}^32
zero←AEAD.Enc(κ9,0,H9,NULL)
m1←MAC(H(lbl3‖spki),type‖0^3‖sidr‖sidi‖ct2‖ct3‖zero)
m2←MAC(cookie,type‖0^3‖sidr‖sidi‖ct2‖ct3‖zero‖m1)
RespHello←type‖0^3‖sidr‖sidi‖ct2‖ct3‖zero‖m1‖m2

tki←KDF1(C9,NULL)
tkr←KDF2(C9,NULL)
