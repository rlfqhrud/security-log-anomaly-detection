"""룰 히트를 받아 entity(세션 단위 임시 식별자)별 위험 점수를 누적하고
위험도를 분류하는 채점기. 출발지 IP는 조사 참고용으로 함께 집계한다.

등급 임계값/참고 라벨은 risk_config.py(risk_levels.yaml 기반)에서 가져온다
- 하드코딩하지 않는다."""

from collections import defaultdict

from risk_config import HIGH_RISK, LOW_RISK, MEDIUM_RISK, classify

__all__ = ["RiskScorer", "LOW_RISK", "MEDIUM_RISK", "HIGH_RISK"]


class RiskScorer:
    def __init__(self):
        self._scores = defaultdict(float)
        self._attack_types = defaultdict(set)
        self._hits = defaultdict(list)
        self._source_ips = defaultdict(set)

    def add_hits(self, hits):
        for hit in hits:
            entity = hit["entity"]
            self._scores[entity] = min(1.0, self._scores[entity] + hit["score"])
            self._attack_types[entity].add(hit["attack_type"])
            self._hits[entity].append(hit)
            if hit.get("source_ip"):
                self._source_ips[entity].add(hit["source_ip"])

    @staticmethod
    def classify(score):
        return classify(score)

    def results(self):
        """entity별 점수/위험도/공격유형을 점수 내림차순으로 반환한다.
        score_breakdown에 "어떤 룰이 몇 점을 기여했는지"를 그대로 남겨서
        왜 이 등급인지 알림/대시보드에서 보여줄 수 있게 한다."""
        results = []
        for entity, score in self._scores.items():
            hits = self._hits[entity]
            results.append({
                "entity": entity,
                "score": round(score, 2),
                "level": self.classify(score),
                "attack_types": sorted(self._attack_types[entity]),
                "details": [h["detail"] for h in hits],
                "source_ips": sorted(self._source_ips[entity]),
                "score_breakdown": [
                    {
                        "attack_type": h["attack_type"],
                        "score": h["score"],
                        "detail": h["detail"],
                    }
                    for h in hits
                ],
            })
        results.sort(key=lambda r: r["score"], reverse=True)
        return results

    def incidents(self):
        """고위험으로 분류된 entity만 반환한다."""
        return [r for r in self.results() if r["level"] == HIGH_RISK]
