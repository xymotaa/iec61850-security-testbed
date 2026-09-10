"""
ids_core.py — lógica de detecção de anomalias GOOSE (Testes A–D da metodologia).

Mantido separado da captura de rede de propósito, pra poder testar a
lógica de detecção inteira com dados sintéticos, sem precisar de tráfego
real — mesma estratégia usada em goose_frame.py.

Cada instância de GooseMonitor mantém o estado observado por gocbRef
(o "identificador" de um fluxo publisher/assinante GOOSE) e, a cada
frame processado, retorna os alertas gerados (lista vazia se nada
suspeito).
"""
from collections import defaultdict, deque

FLOOD_WINDOW_SECONDS = 2.0
FLOOD_PPS_THRESHOLD = 20       # pacotes/seg sustentados no mesmo gocbRef
SUPPRESSION_JUMP_THRESHOLD = 50  # salto de stNum considerado implausível


class GooseMonitor:
    def __init__(self, flood_pps_threshold=FLOOD_PPS_THRESHOLD,
                 flood_window=FLOOD_WINDOW_SECONDS,
                 suppression_jump=SUPPRESSION_JUMP_THRESHOLD):
        self.flood_pps_threshold = flood_pps_threshold
        self.flood_window = flood_window
        self.suppression_jump = suppression_jump

        # gocbRef -> dict com último stNum/sqNum/src_mac visto
        self._last = {}
        # gocbRef -> deque de timestamps recentes (pra taxa de pacotes)
        self._recent_times = defaultdict(deque)
        # gocbRef -> estado do flood em andamento (pra só alertar na borda)
        self._flood_state = {}

    def process(self, gocb_ref, src_mac, st_num, sq_num, timestamp):
        """Processa um frame GOOSE (já parseado) e retorna uma lista de
        alertas (dicts com 'type', 'gocb_ref', 'detail'). Lista vazia
        significa que nada suspeito foi detectado neste frame."""
        alerts = []

        alerts += self._check_flood(gocb_ref, timestamp)

        last = self._last.get(gocb_ref)
        if last is not None:
            alerts += self._check_masquerade(gocb_ref, src_mac, last)
            alerts += self._check_replay(gocb_ref, st_num, sq_num, last)
            alerts += self._check_suppression(gocb_ref, st_num, last)

        # atualiza o estado — só avança stNum/sqNum se não for replay,
        # pra não "validar" um valor antigo como se fosse o mais recente
        is_replay = any(a["type"] == "replay" for a in alerts)
        if not is_replay:
            self._last[gocb_ref] = {
                "src_mac": src_mac, "st_num": st_num, "sq_num": sq_num,
            }
        else:
            # mesmo em replay, atualiza o MAC de origem visto por último
            # (não teria sentido comparar masquerade contra um MAC velho)
            self._last[gocb_ref]["src_mac"] = src_mac

        return alerts

    def _check_flood(self, gocb_ref, timestamp):
        """Só gera alerta na BORDA (início e fim do flood), não a cada
        pacote — enquanto o flood continua sustentado, fica em silêncio
        e só acompanha o pico de taxa internamente."""
        times = self._recent_times[gocb_ref]
        times.append(timestamp)
        while times and timestamp - times[0] > self.flood_window:
            times.popleft()
        pps = len(times) / self.flood_window

        state = self._flood_state.setdefault(
            gocb_ref, {"active": False, "start_time": None, "peak_pps": 0.0}
        )

        if pps > self.flood_pps_threshold:
            if not state["active"]:
                state["active"] = True
                state["start_time"] = timestamp
                state["peak_pps"] = pps
                return [{"type": "flood_start", "gocb_ref": gocb_ref,
                         "detail": f"{pps:.1f} pkts/s (limite: {self.flood_pps_threshold})"}]
            state["peak_pps"] = max(state["peak_pps"], pps)
            return []
        else:
            alert = self._close_flood(gocb_ref, state, timestamp)
            return [alert] if alert else []

    def _close_flood(self, gocb_ref, state, timestamp):
        """Encerra um flood em andamento (usado tanto quando um pacote
        chega com taxa já normalizada quanto pelo tick() por tempo)."""
        if not state["active"]:
            return None
        duration = timestamp - state["start_time"]
        detail = (f"encerrado após {duration:.1f}s, "
                  f"pico de {state['peak_pps']:.1f} pkts/s")
        state["active"] = False
        state["start_time"] = None
        state["peak_pps"] = 0.0
        return {"type": "flood_end", "gocb_ref": gocb_ref, "detail": detail}

    def tick(self, timestamp):
        """Reavalia o estado de flood mesmo sem nenhum pacote novo chegar.
        Necessário porque, sem tráfego de fundo legítimo (heartbeat GOOSE
        contínuo), o fim de um flood nunca teria um 'próximo pacote' pra
        disparar a checagem — chame isso periodicamente (ex: a cada 1s)
        no loop principal do IDS."""
        alerts = []
        for gocb_ref, state in self._flood_state.items():
            if not state["active"]:
                continue
            times = self._recent_times[gocb_ref]
            while times and timestamp - times[0] > self.flood_window:
                times.popleft()
            pps = len(times) / self.flood_window
            if pps <= self.flood_pps_threshold:
                alert = self._close_flood(gocb_ref, state, timestamp)
                if alert:
                    alerts.append(alert)
        return alerts

    def _check_masquerade(self, gocb_ref, src_mac, last):
        if src_mac != last["src_mac"]:
            return [{"type": "masquerade", "gocb_ref": gocb_ref,
                     "detail": f"MAC mudou de {last['src_mac']} para {src_mac}"}]
        return []

    def _check_replay(self, gocb_ref, st_num, sq_num, last):
        if (st_num, sq_num) <= (last["st_num"], last["sq_num"]):
            return [{"type": "replay", "gocb_ref": gocb_ref,
                     "detail": f"(stNum={st_num}, sqNum={sq_num}) <= último "
                               f"visto (stNum={last['st_num']}, sqNum={last['sq_num']})"}]
        return []

    def _check_suppression(self, gocb_ref, st_num, last):
        jump = st_num - last["st_num"]
        if jump > self.suppression_jump:
            return [{"type": "suppression", "gocb_ref": gocb_ref,
                     "detail": f"stNum saltou de {last['st_num']} para {st_num} "
                               f"(salto de {jump})"}]
        return []
