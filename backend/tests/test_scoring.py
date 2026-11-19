import pytest

from models import Environment, SeverityCounts
from scoring import (
    compute_container_score,
    compute_sast_score,
    compute_sca_score,
    compute_uvs_score,
    risk_band_for,
)


def zero_counts() -> SeverityCounts:
    return SeverityCounts(critical=0, high=0, medium=0, low=0)


class TestSeverityDensityScores:
    def test_zero_findings_scores_zero(self):
        assert compute_sast_score(zero_counts()) == 0.0
        assert compute_container_score(zero_counts()) == 0.0

    def test_all_critical_saturates_at_100(self):
        # 5 criticals * 10 points = 50 points = MAX_FINDING_POINTS -> 100
        counts = SeverityCounts(critical=5, high=0, medium=0, low=0)
        assert compute_sast_score(counts) == 100.0

    def test_more_than_max_points_clamped_not_overflowed(self):
        counts = SeverityCounts(critical=50, high=10, medium=0, low=0)
        assert compute_container_score(counts) == 100.0

    def test_single_low_finding_is_small_but_nonzero(self):
        counts = SeverityCounts(critical=0, high=0, medium=0, low=1)
        score = compute_sast_score(counts)
        assert 0 < score < 5

    def test_severity_ordering_respected(self):
        low_only = compute_sast_score(SeverityCounts(low=4))
        high_only = compute_sast_score(SeverityCounts(high=4))
        critical_only = compute_sast_score(SeverityCounts(critical=4))
        assert low_only < high_only < critical_only


class TestSCAScore:
    def test_zero_findings_no_cvss_scores_zero(self):
        assert compute_sca_score(zero_counts(), mean_cvss=None) == 0.0

    def test_blends_density_and_cvss(self):
        counts = SeverityCounts(critical=2, high=0, medium=0, low=0)  # density=40
        # cvss=10 -> cvss_component=100 ; blend = 0.5*40 + 0.5*100 = 70
        score = compute_sca_score(counts, mean_cvss=10.0)
        assert score == 70.0

    def test_cvss_capped_at_100_equivalent(self):
        counts = SeverityCounts(critical=5)  # density = 100
        score = compute_sca_score(counts, mean_cvss=10.0)
        assert score == 100.0

    def test_falls_back_to_density_when_cvss_missing_but_findings_exist(self):
        counts = SeverityCounts(medium=5)
        score = compute_sca_score(counts, mean_cvss=None)
        assert score == compute_container_score(counts)  # same density formula


class TestRiskBands:
    @pytest.mark.parametrize(
        "score,expected_level",
        [
            (0, "Low"),
            (20, "Low"),
            (20.5, "Medium"),
            (21, "Medium"),
            (50, "Medium"),
            (50.5, "High"),
            (51, "High"),
            (75, "High"),
            (75.5, "Critical"),
            (76, "Critical"),
            (100, "Critical"),
        ],
    )
    def test_band_boundaries(self, score, expected_level):
        level, _ = risk_band_for(score)
        assert level == expected_level


class TestComputeUVSScore:
    def test_clean_commit_scores_zero(self):
        result = compute_uvs_score(
            sast_counts=zero_counts(),
            sca_counts=zero_counts(),
            sca_mean_cvss=None,
            container_counts=zero_counts(),
            environment=Environment.dev,
            previous_final_score=None,
        )
        assert result.final_score == 0.0
        assert result.risk_level == "Low"

    def test_dev_vs_prod_environment_multiplier_changes_score(self):
        sast = SeverityCounts(high=2)
        sca = SeverityCounts(medium=2)
        container = SeverityCounts(low=2)

        dev_result = compute_uvs_score(sast, sca, None, container, Environment.dev, None)
        prod_result = compute_uvs_score(sast, sca, None, container, Environment.prod, None)

        assert prod_result.final_score > dev_result.final_score
        assert prod_result.environment_multiplier == 1.3
        assert dev_result.environment_multiplier == 1.0

    def test_delta_factor_rewards_improvement(self):
        sast = SeverityCounts(medium=1)
        sca = SeverityCounts(medium=1)
        container = SeverityCounts(medium=1)

        # Previous commit was much worse (raw_score of this commit is lower)
        result = compute_uvs_score(sast, sca, None, container, Environment.dev, previous_final_score=90.0)
        assert result.delta_factor == 0.9

    def test_delta_factor_does_not_reward_regression(self):
        sast = SeverityCounts(critical=5)
        sca = SeverityCounts(critical=5)
        container = SeverityCounts(critical=5)

        result = compute_uvs_score(sast, sca, None, container, Environment.dev, previous_final_score=1.0)
        assert result.delta_factor == 1.0

    def test_first_commit_uses_neutral_delta_factor(self):
        result = compute_uvs_score(
            SeverityCounts(high=1), SeverityCounts(high=1), None, SeverityCounts(high=1),
            Environment.dev, previous_final_score=None,
        )
        assert result.delta_factor == 1.0

    def test_all_critical_prod_commit_is_blocked_critical(self):
        counts = SeverityCounts(critical=10)
        result = compute_uvs_score(counts, counts, 10.0, counts, Environment.prod, None)
        assert result.final_score == 100.0
        assert result.risk_level == "Critical"
        assert "Block merge" in result.recommended_action

    def test_final_score_never_exceeds_100(self):
        counts = SeverityCounts(critical=999)
        result = compute_uvs_score(counts, counts, 10.0, counts, Environment.prod, previous_final_score=5.0)
        assert result.final_score <= 100.0

    def test_per_finding_multipliers_increase_score(self):
        counts = SeverityCounts(high=1)
        baseline = compute_uvs_score(
            zero_counts(), zero_counts(), None, counts, Environment.dev, None
        )
        bumped = compute_uvs_score(
            zero_counts(), zero_counts(), None, counts, Environment.dev, None, container_points=7.1
        )
        assert bumped.final_score > baseline.final_score

    def test_weights_sum_matches_prd_spec(self):
        from scoring import W_CONTAINER, W_SAST, W_SCA
        assert W_SAST == 0.35
        assert W_SCA == 0.40
        assert W_CONTAINER == 0.25
        assert round(W_SAST + W_SCA + W_CONTAINER, 2) == 1.0
