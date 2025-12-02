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
    total_kill_count = 0
    mutant_set = set()
    trials = 100
    for i in range(trials):
        result, _, coverage_increased = fuzzer.run(runner)
        print(f"Fuzzing iteration #{i + 1} input: {fuzzer.inp}")
        if not coverage_increased:
            kill_count, mutant_set = run_mutation_tests(original_sentence, fuzzer.inp, result, mutant_set)
            if kill_count > total_kill_count:
                total_kill_count = kill_count
                seed = Seed(fuzzer.inp)
                seed.coverage = runner.coverage()
                fuzzer.add_to_population(seed)
            clear_survived_mutants()
            reset_sut_source_code()
        print()
    print("Fuzzing loop ended.")
    print(f"Unique executions paths discovered: {len(fuzzer.coverages_seen)}")
    print(f"Mutants killed: {total_kill_count} out of {len(mutant_set)}")
    print(f"Mutation score: {total_kill_count / len(mutant_set) * 100:.2f}%")


def run_mutation_tests(original_sentence, input_str, expected_output, mutant_set):
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
    kill_count, mutant_set = get_mutation_test_results_from_db(mutant_set)
    print(f"{kill_count} killed mutants out of {len(mutant_set)}")
    print(f"Mutation score: {kill_count / len(mutant_set) * 100:.2f}%")
    return kill_count, mutant_set


def get_mutation_test_results_from_db(mutant_set):
    conn = sqlite3.connect(COSMIC_RAY_SESSION)
    cursor = conn.cursor()
    cursor.execute("SELECT job_id, test_outcome FROM work_results")
    result = list(cursor.fetchall())
    conn.close()
    killed = 0
    for record in result:
        mutant_set.add(record[0])
        if record[1] == "KILLED":
            killed += 1
    return killed, mutant_set


def clear_survived_mutants():
    conn = sqlite3.connect(COSMIC_RAY_SESSION)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM work_results WHERE test_outcome != 'KILLED'")
    conn.commit()
    conn.close()
