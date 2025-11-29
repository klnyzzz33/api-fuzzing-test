from test_gec_tagging import MUTATION_BRIDGE
from zeeguu.core.nlp_pipeline.automatic_gec_tagging import AutoGECTagging
from zeeguu.core.nlp_pipeline import SPACY_EN_MODEL

AGT = AutoGECTagging(SPACY_EN_MODEL, 'en')

def test_gec_mutpy_bridge():
    fuzzed_input = MUTATION_BRIDGE["FUZZED_INPUT"]
    expected = MUTATION_BRIDGE["EXPECTED_OUTPUT"]

    print(f"In mutation FUZZED_INPUT #{MUTATION_BRIDGE['FUZZED_INPUT']}")
    print(f"In mutation EXPECTED_OUTPUT #{MUTATION_BRIDGE['EXPECTED_OUTPUT']}")

    user_tokens = fuzzed_input.split(" ")
    word_dict_list = [{"word": w, "isInSentence": True} for w in user_tokens]
    assert AGT.anottate_clues(word_dict_list, fuzzed_input) == expected
