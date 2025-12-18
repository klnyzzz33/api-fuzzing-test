import inspect
import json
import os
import sqlite3
import time
from typing import List

from cosmic_ray.cli import handle_exec_inprocess_batch
from fuzzingbook.Grammars import Grammar
from fuzzingbook.GreyboxFuzzer import AFLFastSchedule, Seed, PowerSchedule
from fuzzingbook.MutationFuzzer import FunctionCoverageRunner

from zeeguu.core.test.fuzzing_test.gec_fuzzer import CountingGreyboxFuzzer, UnguidedFuzzer
from zeeguu.core.test.fuzzing_test.gec_generate_seed import gec_generate_seed
from zeeguu.core.test.fuzzing_test.gec_mutator import GecMutator
from zeeguu.core.test.fuzzing_test.test_gec_tagging_setup import COSMIC_RAY_CONFIG, COSMIC_RAY_SESSION
from zeeguu.core.test.fuzzing_test.test_gec_tagging_setup import reset_sut_source_code
from zeeguu.core.test.fuzzing_test.test_gec_tagging_setup import test_env, MUTATION_BRIDGE_FILE_PATH

GEC_INPUT_GRAMMAR: Grammar = {
    "<start>": ["<sentence>"],
    "<sentence>": ["<sent_parts> <sent_parts> <sent_parts>"],
    "<sent_parts>": ["<token>", "<token> <sent_parts>"],
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


def test_gec_tagging_labels(test_env):
    original_sentence = gec_generate_seed(grammar=GEC_INPUT_GRAMMAR)
    print(f"\nOriginal sentence: {original_sentence}")

    def annotate_clues_wrapper(mutated_sentence: str):
        from zeeguu.core.nlp_pipeline import AutoGECTagging, SPACY_EN_MODEL
        agt = AutoGECTagging(SPACY_EN_MODEL, 'en')
        user_tokens = mutated_sentence.split(" ")
        word_dictionary_list = [{"word": w, "isInSentence": True} for w in user_tokens]
        print("Before")
        result = agt.anottate_clues(word_dictionary_list, original_sentence)
        print("After")

    max_seconds = 60

    unguided_fuzz(annotate_clues_wrapper, original_sentence, max_seconds)
    coverage_guided_fuzz(annotate_clues_wrapper, original_sentence, max_seconds)
    mutation_guided_fuzz(annotate_clues_wrapper, original_sentence, max_seconds)


def unguided_fuzz(method, original_sentence, max_seconds):
    print("\nStarting unguided fuzzing...\n")
    seeds = [original_sentence]
    runner = FunctionCoverageRunner(method)
    fuzzer = UnguidedFuzzer(seeds, MUTATOR, PowerSchedule())
    i = 0
    end_time = time.time() + max_seconds
    while time.time() < end_time:
        result, _ = fuzzer.run(runner)
        print(f"Fuzzing iteration #{i + 1} input: {fuzzer.inp}")
        i += 1
    fuzzer.save_population('unguided', original_sentence)
    print("Fuzzing loop ended.")
    print(f"Unique executions paths discovered: {len(fuzzer.coverages_seen)}")


def coverage_guided_fuzz(method, original_sentence, max_seconds):
    print("\nStarting coverage-guided fuzzing...\n")
    seeds = [original_sentence]
    runner = FunctionCoverageRunner(method)
    fuzzer = CountingGreyboxFuzzer(seeds, MUTATOR, AFLFastSchedule(5))
    i = 0
    end_time = time.time() + max_seconds
    while time.time() < end_time:
        result, _, coverage_increased = fuzzer.run(runner)
        print(f"Fuzzing iteration #{i + 1} input: {fuzzer.inp}")
        i += 1
    fuzzer.save_population('coverage-guided', original_sentence)
    print("Fuzzing loop ended.")
    print(f"Unique executions paths discovered: {len(fuzzer.coverages_seen)}")


def mutation_guided_fuzz(method, original_sentence, max_seconds):
    print("\nStarting mutation testing-guided fuzzing...\n")
    seeds = [original_sentence]
    runner = FunctionCoverageRunner(method)
    fuzzer = CountingGreyboxFuzzer(seeds, MUTATOR, AFLFastSchedule(5))
    total_kill_count = 0
    mutant_set = set()
    false_positives_timeout = 0
    false_positives_error = 0
    i = 0
    end_time = time.time() + max_seconds
    while time.time() < end_time:
        result, _, coverage_increased = fuzzer.run(runner)
        print(f"Fuzzing iteration #{i + 1} input: {fuzzer.inp}")
        if not coverage_increased:
            kill_count, mutant_set, false_positives_timeout, false_positives_error = run_mutation_tests(
                original_sentence, fuzzer.inp, result, mutant_set, runner.coverage())
            if kill_count > total_kill_count:
                total_kill_count = kill_count
                seed = Seed(fuzzer.inp)
                seed.coverage = runner.coverage()
                fuzzer.add_to_population(seed, result)
            clear_skipped_and_survived_mutants()
            reset_sut_source_code()
        i += 1
    fuzzer.save_population('mutation-guided', original_sentence)
    print("Fuzzing loop ended.")
    print(f"Unique executions paths discovered: {len(fuzzer.coverages_seen)}")
    print(f"Mutants killed: {total_kill_count} out of {len(mutant_set)}")
    print(f"Mutation score: {total_kill_count / len(mutant_set) * 100 if len(mutant_set) > 0 else 0:.2f}%")
    print(f"Timeout false positives: {false_positives_timeout}")
    print(f"System under test error false positives: {false_positives_error}")


def run_mutation_tests(original_sentence, input_str, expected_output, mutant_set, coverage):
    with open(MUTATION_BRIDGE_FILE_PATH, 'w') as f:
        json.dump({"ORIGINAL_SENTENCE": original_sentence, "MUTATED_SENTENCE": input_str,
                   "EXPECTED_OUTPUT": expected_output}, f)
    try:
        print("Coverage not increased. Starting mutation testing...")
        candidate_mutations = filter_killable_mutants(coverage)
        if not candidate_mutations:
            print("Nothing to test in current iteration, skipping mutation testing.\n")
            kill_count, mutant_set, false_positives_timeout, false_positives_error = get_mutation_test_results_from_db(
                mutant_set)
            return kill_count, mutant_set, false_positives_timeout, false_positives_error
        handle_exec_inprocess_batch(COSMIC_RAY_CONFIG, COSMIC_RAY_SESSION)
    except Exception as e:
        print(f"Unexpected error: {e}")
    print("Mutation testing ended.")
    kill_count, mutant_set, false_positives_timeout, false_positives_error = get_mutation_test_results_from_db(
        mutant_set)
    print(f"{kill_count} killed mutants out of {len(mutant_set)}")
    print(f"Mutation score: {kill_count / len(mutant_set) * 100:.2f}%")
    print(f"Timeout false positives: {false_positives_timeout}")
    print(f"System under test error false positives: {false_positives_error}\n")
    return kill_count, mutant_set, false_positives_timeout, false_positives_error


def filter_killable_mutants(coverage):
    killable_mutation_specs = get_killable_mutation_specs_from_db()
    coverage_with_module_names = get_coverage_with_module_names(coverage)
    skip_job_ids = []
    candidate_job_ids = []
    for module_path, start_pos_row, job_id in killable_mutation_specs:
        if (module_path, start_pos_row) not in coverage_with_module_names:
            skip_job_ids.append(job_id)
        else:
            candidate_job_ids.append(job_id)
    if skip_job_ids:
        insert_skipped_work_results(skip_job_ids)
    return candidate_job_ids


def get_killable_mutation_specs_from_db():
    conn = sqlite3.connect(COSMIC_RAY_SESSION)
    cursor = conn.cursor()
    cursor.execute("""
                   SELECT module_path, start_pos_row, ms.job_id
                   FROM mutation_specs ms LEFT JOIN work_results wr ON ms.job_id = wr.job_id
                   WHERE wr.job_id IS NULL OR wr.test_outcome != 'KILLED'
                   """)
    result = list(cursor.fetchall())
    conn.close()
    return result


def get_coverage_with_module_names(coverage):
    sut_mapping = get_sut_method_module_mapping()
    result = set()
    for method_name, func_line in coverage:
        if (method_name, func_line) in sut_mapping:
            module_path = sut_mapping[(method_name, func_line)]
            result.add((module_path, func_line))
    return result


def get_sut_method_module_mapping():
    from zeeguu.core.nlp_pipeline import AutoGECTagging
    mapping = {}
    for method_name, method in inspect.getmembers(AutoGECTagging, predicate=inspect.isfunction):
        module_path = os.path.relpath(inspect.getfile(method))
        source_lines, start_line = inspect.getsourcelines(method)
        for i in range(len(source_lines)):
            func_line = start_line + i
            mapping[(method_name, func_line)] = module_path
    return mapping


def insert_skipped_work_results(job_ids):
    conn = sqlite3.connect(COSMIC_RAY_SESSION)
    cursor = conn.cursor()
    for job_id in job_ids:
        cursor.execute("""
                       INSERT INTO work_results (worker_outcome, output, test_outcome, diff, job_id)
                       VALUES ('SKIPPED', '', 'INCOMPETENT', '', ?)
                       """, (job_id,))
    conn.commit()
    conn.close()


def get_mutation_test_results_from_db(mutant_set):
    conn = sqlite3.connect(COSMIC_RAY_SESSION)
    cursor = conn.cursor()
    cursor.execute("SELECT job_id, test_outcome FROM work_results WHERE worker_outcome != 'SKIPPED'")
    result = list(cursor.fetchall())
    killed = 0
    for record in result:
        mutant_set.add(record[0])
        if record[1] == "KILLED":
            killed += 1
    cursor.execute("""
                   SELECT count(*)
                   FROM work_results
                   WHERE test_outcome = 'KILLED' AND output = 'timeout'
                   """)
    false_positives_timeout = int(cursor.fetchone()[0])
    cursor.execute("""
                   SELECT count(*)
                   FROM work_results
                   WHERE test_outcome = 'KILLED' AND output NOT LIKE '%SUT return value:%'
                   """)
    false_positives_error = int(cursor.fetchone()[0]) - false_positives_timeout
    conn.close()
    return killed, mutant_set, false_positives_timeout, false_positives_error


def clear_skipped_and_survived_mutants():
    conn = sqlite3.connect(COSMIC_RAY_SESSION)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM work_results WHERE worker_outcome = 'SKIPPED' OR test_outcome != 'KILLED'")
    conn.commit()
    conn.close()
