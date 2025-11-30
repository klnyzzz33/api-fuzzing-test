import json
import os
import sqlite3
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

AGT = AutoGECTagging(SPACY_EN_MODEL, 'en')

MUTATION_TESTING_DIR = "./mutation_testing"
MUTATION_BRIDGE_FILE_PATH = f"{MUTATION_TESTING_DIR}/mutation_bridge.json"
if not os.path.exists(MUTATION_BRIDGE_FILE_PATH):
    with open(MUTATION_BRIDGE_FILE_PATH, 'w') as file:
        file.write("")


def test_gec_tagging_labels(test_env):
    original_sentence = gec_generate_seed(grammar=GEC_INPUT_GRAMMAR)
    seeds = [original_sentence]
    print(f"\nOriginal sentence: {original_sentence}\n")

    def annotate_clues_wrapper(mutated_sentence: str) -> Any:
        user_tokens = mutated_sentence.split(" ")
        word_dictionary_list = [{"word": w, "isInSentence": True} for w in user_tokens]
        return AGT.anottate_clues(word_dictionary_list, original_sentence)

    runner = FunctionCoverageRunner(annotate_clues_wrapper)
    fuzzer = CountingGreyboxFuzzer(seeds, MUTATOR, POWER_SCHEDULE)

    trials = 3
    for i in range(trials):
        [result, outcome] = fuzzer.run(runner)

        print(f"FUZZED_INPUT: {fuzzer.inp}")
        print(f"EXPECTED_OUTPUT: {result}")

        check_kills_new_mutant(fuzzer.inp, result)

    # print(f"Unique paths discovered: {len(fuzzer.coverages_seen)}")


def check_kills_new_mutant(input_str, expected_output):
    with open(MUTATION_BRIDGE_FILE_PATH, 'w') as f:
        json.dump({"FUZZED_INPUT": input_str, "EXPECTED_OUTPUT": expected_output}, f)

    cosmic_ray_script = which("cosmic-ray")
    if cosmic_ray_script is None:
        raise RuntimeError("\"cosmic-ray\" not found in PATH. Make sure CosmicRay is installed in this environment.")

    cosmic_ray_config = f"{MUTATION_TESTING_DIR}/cosmic_ray_gec_tagging.toml"
    cosmic_ray_session = f"{MUTATION_TESTING_DIR}/cosmic_ray_gec_tagging.sqlite"
    cmd = [
        sys.executable, "-m", "cosmic_ray.cli",
        "exec",
        cosmic_ray_config,
        cosmic_ray_session
    ]

    try:
        subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=os.path.abspath("."),
            timeout=10
        )

    except subprocess.TimeoutExpired:
        ...
    except Exception as e:
        print(f"Error running cosmic-ray: {e}")
        return False

    mutant_states = get_killed_mutants_from_db(cosmic_ray_session)
    print(f"Killed {mutant_states['KILLED']} mutants out of {mutant_states['KILLED'] + mutant_states['SURVIVED']}")
    print(f"Mutation score: {mutant_states['KILLED'] / (mutant_states['KILLED'] + mutant_states['SURVIVED']) * 100}%\n")
    return True


def get_killed_mutants_from_db(cosmic_ray_session):
    conn = sqlite3.connect(cosmic_ray_session)
    cursor = conn.cursor()
    cursor.execute("SELECT test_outcome, count(*) FROM work_results GROUP BY test_outcome")
    result = dict(cursor.fetchall())
    conn.close()
    return result
