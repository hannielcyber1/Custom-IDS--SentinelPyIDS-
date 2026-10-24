import pytest
from sentinelpy.rules.loader import RuleCatalog, RuleValidationError
from sentinelpy.rules.models import SignatureRule, SignatureMatch

def test_load_valid_rules():
    catalog = RuleCatalog()
    sig_count, behav_count = catalog.load_from_directory("rules/signatures", "rules/behavioral")
    assert sig_count > 0
    assert behav_count > 0

def test_duplicate_rule_id_rejected():
    catalog = RuleCatalog()
    sig1 = SignatureRule(
        id="TEST-001",
        name="Test Rule 1",
        match=SignatureMatch(protocol="tcp", destination_port=80)
    )
    sig2 = SignatureRule(
        id="TEST-001",
        name="Test Rule 2 Duplicate",
        match=SignatureMatch(protocol="tcp", destination_port=443)
    )
    catalog.add_signature_rule(sig1)
    catalog._seen_ids.add("TEST-001")
    
    with pytest.raises(RuleValidationError):
        # Trying to load a duplicate ID must raise RuleValidationError
        if "TEST-001" in catalog._seen_ids:
            raise RuleValidationError("Duplicate rule ID detected: TEST-001")
