import json
import sqlite3
import sys

from cosmic_ray.cli import handle_exec_inprocess

from zeeguu.core.test.fuzzing_test.gec_fuzzer import TestResult
from zeeguu.core.test.fuzzing_test.test_gec_tagging_setup import COSMIC_RAY_CONFIG, COSMIC_RAY_SESSION
from zeeguu.core.test.fuzzing_test.test_gec_tagging_setup import MUTATION_BRIDGE_FILE_PATH
from zeeguu.core.test.fuzzing_test.test_gec_tagging_setup import reset_gec_test, reset_sut_source_code


def main(arguments):
    if len(arguments) != 4:
        print(f"Usage: python {sys.argv[0]} result_file_1 result_file_2 result_file_3")
    result_file_name = arguments[1:4]
    eval_results(result_file_name)


def eval_results(result_file_paths):
    results_dir = "zeeguu/core/test/fuzzing_test/results"
    reset_gec_test()
    mutant_count = get_mutant_count()
    for file in result_file_paths:
        test_result = TestResult.from_json(f"{results_dir}/{file}")
        print(f"Original sentence: {test_result.original_sentence}")
        print(f"Corpus size: {len(test_result.corpus_result_mapping)}")
        print(f"Coverage size (unique paths): {len(test_result.coverage)}")
        kill_count = run_eval(test_result.original_sentence, test_result.corpus_result_mapping, mutant_count)
        print(f"Mutants killed: {kill_count}")
        print(f"Mutation score: {kill_count / mutant_count * 100:.2f}%\n")
        reset_gec_test()


def run_eval(original_sentence, corpus_result_mapping, mutant_count):
    for i in range(len(corpus_result_mapping)):
        entry = corpus_result_mapping[i]
        input_str = entry["input"]
        output = entry["output"]
        with open(MUTATION_BRIDGE_FILE_PATH, 'w') as f:
            json.dump({"ORIGINAL_SENTENCE": original_sentence, "MUTATED_SENTENCE": input_str,
                       "EXPECTED_OUTPUT": output}, f)
        kills_before = get_mutation_kill_count_from_db()
        handle_exec_inprocess(COSMIC_RAY_CONFIG, COSMIC_RAY_SESSION)
        new_kills = get_mutation_kill_count_from_db() - kills_before
        print(
            f"Input {i + 1}/{len(corpus_result_mapping)}: Killed {new_kills} mutants, {mutant_count - kills_before - new_kills} remaining")
        clear_survived_mutants()
        reset_sut_source_code()
    return get_mutation_kill_count_from_db()


def get_mutant_count():
    conn = sqlite3.connect(COSMIC_RAY_SESSION)
    cursor = conn.cursor()
    cursor.execute("SELECT count(*) FROM mutation_specs")
    result = int(cursor.fetchone()[0])
    conn.close()
    return result


def clear_survived_mutants():
    conn = sqlite3.connect(COSMIC_RAY_SESSION)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM work_results WHERE test_outcome != 'KILLED'")
    conn.commit()
    conn.close()


def get_mutation_kill_count_from_db():
    conn = sqlite3.connect(COSMIC_RAY_SESSION)
    cursor = conn.cursor()
    cursor.execute("SELECT count(*) FROM work_results WHERE test_outcome = 'KILLED'")
    result = int(cursor.fetchone()[0])
    conn.close()
    return result


if __name__ == '__main__':
    main(sys.argv)
