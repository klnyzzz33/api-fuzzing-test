import json
import os

from zeeguu.core.test.fuzzing_test.test_gec_tagging import AGT, MUTATION_BRIDGE_FILE_PATH


def test_gec_mutpy_bridge():
    if not os.path.exists(MUTATION_BRIDGE_FILE_PATH):
        raise FileNotFoundError(f"Mutation bridge file not found: {MUTATION_BRIDGE_FILE_PATH}")

    with open(MUTATION_BRIDGE_FILE_PATH, 'r') as f:
        mutation_bridge = json.load(f)

    fuzzed_input = mutation_bridge["FUZZED_INPUT"]
    expected = mutation_bridge["EXPECTED_OUTPUT"]

    print(f"In mutation FUZZED_INPUT #{mutation_bridge['FUZZED_INPUT']}")
    print(f"In mutation EXPECTED_OUTPUT #{mutation_bridge['EXPECTED_OUTPUT']}")

    user_tokens = fuzzed_input.split(" ")
    word_dict_list = [{"word": w, "isInSentence": True} for w in user_tokens]
    assert AGT.anottate_clues(word_dict_list, fuzzed_input) == expected
