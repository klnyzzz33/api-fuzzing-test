import json

import zeeguu.core.nlp_pipeline.automatic_gec_tagging as agt_module
from zeeguu.core.nlp_pipeline.spacy_wrapper import SpacyWrapper
from zeeguu.core.test.fuzzing_test.test_gec_tagging_setup import MUTATION_BRIDGE_FILE_PATH

SPACY_EN_MODEL = SpacyWrapper("english", False, True)


def test_gec_cosmic_ray_bridge():
    with open(MUTATION_BRIDGE_FILE_PATH, 'r') as f:
        mutation_bridge = json.load(f)

    original_sentence = mutation_bridge["ORIGINAL_SENTENCE"]
    mutated_sentence = mutation_bridge["MUTATED_SENTENCE"]
    expected = mutation_bridge["EXPECTED_OUTPUT"]

    agt = agt_module.AutoGECTagging(SPACY_EN_MODEL, 'en')
    user_tokens = mutated_sentence.split(" ")
    word_dict_list = [{"word": w, "isInSentence": True} for w in user_tokens]
    actual = agt.anottate_clues(word_dict_list, original_sentence)
    print(f"SUT return value: {actual}\n")
    print(f"Expected return value: {expected}\n")
    assert actual == expected
