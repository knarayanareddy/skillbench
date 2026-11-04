"""Independent Acceptance Tests against Reference Oracles for SKB."""
from reference.oracles import sample_diff, paired_bootstrap
import random

def test_paired_bootstrap_sampling():
    random.seed(42)
    # 12 paired observations where treatment is consistently better
    pairs = [(0.8, 0.4) for _ in range(12)]
    diff = sample_diff(pairs)
    assert diff == pytest.approx(0.4)
    
    ci_low, ci_high = paired_bootstrap(pairs, iterations=500)
    assert ci_low <= diff <= ci_high
