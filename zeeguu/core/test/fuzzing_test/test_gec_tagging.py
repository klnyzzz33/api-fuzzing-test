import os
import subprocess
import sys
from shutil import which
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

MUTATION_BRIDGE = {
    "FUZZED_INPUT": None,
    "EXPECTED_OUTPUT": None
}

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

    def annotate_clues_wrapper(mutated_sentence: str) -> Any:
        user_tokens = mutated_sentence.split(" ")
        word_dictionary_list = list(map(lambda w: {"word": w, "isInSentence": True}, user_tokens))
        return AGT.anottate_clues(word_dictionary_list, original_sentence)

    runner = FunctionCoverageRunner(annotate_clues_wrapper)
    fuzzer = CountingGreyboxFuzzer(seeds, MUTATOR, POWER_SCHEDULE)

    trials = 1
    for i in range(trials):
        [result, outcome] = fuzzer.run(runner)
        MUTATION_BRIDGE["FUZZED_INPUT"] = original_sentence
        MUTATION_BRIDGE["EXPECTED_OUTPUT"] = result

        print(f"Original FUZZED_INPUT #{MUTATION_BRIDGE['FUZZED_INPUT']}")
        print(f"Original EXPECTED_OUTPUT #{MUTATION_BRIDGE['EXPECTED_OUTPUT']}")

        run_mutation()

    print(f"Unique paths discovered: {len(fuzzer.coverages_seen)}")


def run_mutation():
    mutpy_script = which("mut.py")
    if mutpy_script is None:
        raise RuntimeError("mut.py not found in PATH. Make sure MutPy is installed in this environment.")

    cmd = [
        sys.executable,
        mutpy_script,
        "--target", "zeeguu.core.nlp_pipeline.automatic_gec_tagging",
        "--unit-test", "zeeguu.core.test.fuzzing_test.test_gec_mutation_bridge",
        "-m"
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=os.path.abspath(".")
    )

    print("=== MutPy STDOUT ===")
    print(result.stdout)

    print("=== MutPy STDERR ===")
    print(result.stderr)
