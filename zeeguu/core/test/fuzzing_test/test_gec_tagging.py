import json
import os
import sqlite3
import subprocess
import sys
from typing import List

from fuzzingbook.Grammars import Grammar
from fuzzingbook.GreyboxFuzzer import AFLFastSchedule, Seed
from fuzzingbook.MutationFuzzer import FunctionCoverageRunner

from zeeguu.core.test.fuzzing_test.gec_fuzzer import CountingGreyboxFuzzer
from zeeguu.core.test.fuzzing_test.gec_generate_seed import gec_generate_seed
from zeeguu.core.test.fuzzing_test.gec_mutator import GecMutator
from zeeguu.core.test.fuzzing_test.test_gec_tagging_setup import COSMIC_RAY_CONFIG, COSMIC_RAY_SESSION
from zeeguu.core.test.fuzzing_test.test_gec_tagging_setup import reset_sut_source_code
from zeeguu.core.test.fuzzing_test.test_gec_tagging_setup import test_env, MUTATION_BRIDGE_FILE_PATH

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

TERMINALS: list[str] = sorted({
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

MUTATOR = GecMutator(TERMINALS, GEC_REPLACE)

POWER_SCHEDULE = AFLFastSchedule(5)


def test_gec_tagging_labels(test_env):
    original_sentence = gec_generate_seed(grammar=GEC_INPUT_GRAMMAR)
    seeds = [original_sentence]
    print(f"\nOriginal sentence: {original_sentence}\n")

    def annotate_clues_wrapper(mutated_sentence: str):
        from zeeguu.core.nlp_pipeline import AutoGECTagging, SPACY_EN_MODEL
        agt = AutoGECTagging(SPACY_EN_MODEL, 'en')
        user_tokens = mutated_sentence.split(" ")
        word_dictionary_list = [{"word": w, "isInSentence": True} for w in user_tokens]
        return agt.anottate_clues(word_dictionary_list, original_sentence)

    runner = FunctionCoverageRunner(annotate_clues_wrapper)
    fuzzer = CountingGreyboxFuzzer(seeds, MUTATOR, POWER_SCHEDULE)

    print("Starting fuzzing loop...\n")
    kill_count = 0
    trials = 100
    for i in range(trials):
        result, _, coverage_increased = fuzzer.run(runner)
        print(f"Fuzzing iteration #{i + 1} input: {fuzzer.inp}")
        if not coverage_increased:
            new_kill_count = run_mutation_tests(original_sentence, fuzzer.inp, result)
            if new_kill_count > kill_count:
                kill_count = new_kill_count
                seed = Seed(fuzzer.inp)
                seed.coverage = runner.coverage()
                fuzzer.add_to_population(seed)
            reset_sut_source_code()
        print()
    print("Fuzzing loop ended.")
    print(f"Unique executions paths discovered: {len(fuzzer.coverages_seen)}")
    killed_mutants, survived_mutants = get_mutation_test_results_from_db()
    print(f"Mutants killed: {killed_mutants} out of {killed_mutants + survived_mutants}")
    print(f"Mutation score: {killed_mutants / (killed_mutants + survived_mutants) * 100:.2f}%")


def run_mutation_tests(original_sentence, input_str, expected_output):
    with open(MUTATION_BRIDGE_FILE_PATH, 'w') as f:
        json.dump({"ORIGINAL_SENTENCE": original_sentence, "MUTATED_SENTENCE": input_str,
                   "EXPECTED_OUTPUT": expected_output}, f)
    try:
        print("Coverage not increased. Starting mutation testing...")
        subprocess.run(
            [sys.executable, "-m", "cosmic_ray.cli", "exec", COSMIC_RAY_CONFIG, COSMIC_RAY_SESSION],
            capture_output=True,
            text=True,
            cwd=os.path.abspath("."),
            timeout=30
        )
    except subprocess.TimeoutExpired:
        ...
    except Exception as e:
        print(f"Unexpected error: {e}")
    print("Mutation testing ended.")
    killed_mutants, survived_mutants = get_mutation_test_results_from_db()
    print(f"{killed_mutants} killed mutants out of {killed_mutants + survived_mutants}")
    print(f"Mutation score: {killed_mutants / (killed_mutants + survived_mutants) * 100:.2f}%")
    return killed_mutants


def get_mutation_test_results_from_db():
    conn = sqlite3.connect(COSMIC_RAY_SESSION)
    cursor = conn.cursor()
    cursor.execute("SELECT test_outcome, count(*) FROM work_results GROUP BY test_outcome")
    result = dict(cursor.fetchall())
    conn.close()
    killed_mutants = result['KILLED'] if 'KILLED' in result else 0
    survived_mutants = result['SURVIVED'] if 'SURVIVED' in result else 0
    return killed_mutants, survived_mutants
