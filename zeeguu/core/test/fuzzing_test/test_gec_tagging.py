from typing import List, Any

from fuzzingbook.Grammars import Grammar
from fuzzingbook.GreyboxFuzzer import AFLFastSchedule
from fuzzingbook.MutationFuzzer import FunctionCoverageRunner

from zeeguu.core.nlp_pipeline import SPACY_EN_MODEL
from zeeguu.core.nlp_pipeline.automatic_gec_tagging import AutoGECTagging
from zeeguu.core.test.fuzzing_test.gec_fuzzer import CountingGreyboxFuzzer
from zeeguu.core.test.fuzzing_test.gec_generate_seed import gec_generate_seed
from zeeguu.core.test.fuzzing_test.gec_mutator import GecMutator
from zeeguu.core.test.fuzzing_test.setup import test_env

GEC_INPUT_GRAMMAR: Grammar = {
    "<start>": ["<sentence>"],
    "<sentence>": ["<sent_parts>", "<sent_parts> <sentence>"],
    "<sent_parts>": ["<token>", "<token> <token>"],
    "<token>": ["<noun>", "<verb>", "<prep>", "<adj>", "<adv>", "<pron>", "<punct>"],
    "<noun>": ["cat", "cats", "book", "books", "airplane", "plane"],
    "<verb>": ["am", "are", "is", "was", "were", "go", "goes", "went", "run", "runs", "running", "eat", "eats",
               "eating"],
    "<prep>": ["in", "on", "at", "with", "without", "before", "after"],
    "<adj>": ["big", "small", "tiny", "large", "larger"],
    "<adv>": ["quickly", "slowly", "silently"],
    "<pron>": ["he", "she", "they", "them", "me", "I", "who", "whom"],
    "<punct>": [".", ",", ";", ":", "!"]
}

ALL_WORDS: list[str] = sorted({
    token
    for expansions in GEC_INPUT_GRAMMAR.values()
    for expansion in expansions
    for token in expansion.split()
    if "<" not in token and ">" not in token
})

GEC_REPLACE: dict[str, List[str]] = {
    "cat": ["cats"],
    "cats": ["cat"],
    "book": ["books"],
    "books": ["book"],
    "am": ["are", "is"],
    "are": ["am", "is"],
    "is": ["am", "are"],
    "go": ["goes", "went", "going"],
    "goes": ["go", "went", "going"],
    "went": ["go", "goes", "going"],
    "eat": ["eats", "ate", "eating"],
    "eats": ["eat", "ate", "eating"],
    "ate": ["eat", "eats", "eating"],
    "eating": ["eat", "eats", "ate"],
    "run": ["runs", "ran", "running"],
    "runs": ["run", "ran", "running"],
    "ran": ["run", "runs", "running"],
    "running": ["run", "runs", "running"],
    "I": ["me"],
    "me": ["I"],
    "he": ["she", "it"],
    "she": ["he", "it"],
    "it": ["he", "she"],
    "they": ["them"],
    "them": ["they"],
    "who": ["whom"],
    "whom": ["who"],
    "in": ["on", "at"],
    "on": ["in", "at"],
    "at": ["in", "on"],
    "big": ["bigger", "biggest"],
    "bigger": ["big", "biggest"],
    "biggest": ["bigger", "big"],
    "large": ["larger", "largest"],
    "larger": ["large", "largest"],
    "largest": ["large", "larger"],
    "small": ["smaller", "smallest"],
    "smaller": ["small", "smallest"],
    "smallest": ["smaller", "small"]
}

MUTATOR = GecMutator(ALL_WORDS, GEC_REPLACE)

POWER_SCHEDULE = AFLFastSchedule(5)

AGT = AutoGECTagging(SPACY_EN_MODEL, 'en')


def test_gec_tagging_labels(test_env):
    original_sentence = gec_generate_seed(grammar=GEC_INPUT_GRAMMAR)
    seeds = [original_sentence]
    print(f"\nOriginal sentence: {original_sentence}\n")

    # input_str = seeds[0]
    # for i in range(10):
    #     input_str = MUTATOR.mutate(input_str)
    #     print(input_str)

    def annotate_clues_wrapper(mutated_sentence: str) -> Any:
        user_tokens = mutated_sentence.split(" ")
        word_dictionary_list = list(map(lambda w: {"word": w, "isInSentence": True}, user_tokens))
        return AGT.anottate_clues(word_dictionary_list, original_sentence)

    runner = FunctionCoverageRunner(annotate_clues_wrapper)
    fuzzer = CountingGreyboxFuzzer(seeds, MUTATOR, POWER_SCHEDULE)
    trials = 500
    for i in range(trials):
        fuzzer.run(runner)
        if i % 50 == 0:
            print(f"Running mutation #{i + 1}")
    print(f"Unique paths discovered: {len(fuzzer.coverages_seen)}")
