import json
import os

from zeeguu.core.test.fuzzing_test.test_gec_tagging_setup import MUTATION_BRIDGE_FILE_PATH


def test_gec_cosmic_ray_bridge():
    if not os.path.exists(MUTATION_BRIDGE_FILE_PATH):
        raise FileNotFoundError(f"Mutation bridge file not found: {MUTATION_BRIDGE_FILE_PATH}")

    with open(MUTATION_BRIDGE_FILE_PATH, 'r') as f:
        mutation_bridge = json.load(f)

    original_sentence = mutation_bridge["ORIGINAL_SENTENCE"]
    mutated_sentence = mutation_bridge["MUTATED_SENTENCE"]
    expected = mutation_bridge["EXPECTED_OUTPUT"]
    print(f"\nORIGINAL_SENTENCE: {original_sentence}")
    print(f"MUTATED_SENTENCE: {mutated_sentence}")
    print(f"EXPECTED_OUTPUT: {expected}\n")

    from zeeguu.core.nlp_pipeline import AutoGECTagging, SPACY_EN_MODEL
    agt = AutoGECTagging(SPACY_EN_MODEL, 'en')
    user_tokens = mutated_sentence.split(" ")
    word_dict_list = [{"word": w, "isInSentence": True} for w in user_tokens]
    assert agt.anottate_clues(word_dict_list, original_sentence) == expected
