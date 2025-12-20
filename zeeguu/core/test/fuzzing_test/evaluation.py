import json
import os
import random
import sqlite3
import sys
from dataclasses import dataclass, asdict
from typing import Any

from cosmic_ray.cli import handle_exec_inprocess

from zeeguu.core.test.fuzzing_test.gec_fuzzer import TestResult
from zeeguu.core.test.fuzzing_test.test_gec_tagging_setup import COSMIC_RAY_CONFIG, COSMIC_RAY_SESSION
from zeeguu.core.test.fuzzing_test.test_gec_tagging_setup import MUTATION_BRIDGE_FILE_PATH
from zeeguu.core.test.fuzzing_test.test_gec_tagging_setup import reset_gec_test, reset_sut_source_code


@dataclass
class EvalResult:
    file: str
    original_sentence: str
    corpus_size: int
    coverage_size: int
    mutants_killed: dict[str, dict[str, int]]
    mutant_count: int

    def to_json(self, filename: str) -> None:
        data = asdict(self)
        with open(filename, "w") as f:
            json.dump(data, f, indent=2)

    @staticmethod
    def from_json(filename: str):
        with open(filename, "r") as f:
            data = json.load(f)
        return EvalResult(**data)

    def __str__(self):
        return (
            f"Original sentence: {self.original_sentence}\n"
            f"Corpus size: {self.corpus_size}\n"
            f"Coverage size (unique paths): {self.coverage_size}\n"
            f"Mutants killed: {self.mutants_killed}\n"
            f"Mutant count: {self.mutant_count}\n"
        )


def main(arguments):
    if len(arguments) != 4:
        print(f"Usage: python {sys.argv[0]} result_file_1 result_file_2 result_file_3")
    result_file_name = arguments[1:4]
    result_dir = "zeeguu/core/test/fuzzing_test/results"
    eval_dir = "zeeguu/core/test/fuzzing_test/evaluation"
    if not os.path.exists(result_dir):
        os.makedirs(result_dir)
    if not os.path.exists(eval_dir):
        os.makedirs(eval_dir)
    eval_results(result_file_name, result_dir, eval_dir)


def eval_results(result_file_paths, result_dir, eval_dir):
    reset_gec_test()
    mutant_count = get_mutant_count()
    for file in result_file_paths:
        result_file_name = f"{result_dir}/{file}"
        eval_file_name = f"{eval_dir}/{file}"
        test_result = TestResult.from_json(result_file_name)
        mutants_killed = run_eval(test_result.original_sentence, test_result.corpus_result_mapping)
        eval_result = EvalResult(file=result_file_name,
                                 original_sentence=test_result.original_sentence,
                                 corpus_size=len(test_result.corpus_result_mapping),
                                 coverage_size=test_result.coverage_size,
                                 mutants_killed=mutants_killed,
                                 mutant_count=mutant_count)
        eval_result.to_json(eval_file_name)
        print(eval_result)
        reset_gec_test()


def run_eval(original_sentence, corpus_result_mapping):
    inputs = sample_eval_inputs(corpus_result_mapping, 10)
    result: dict[str, dict[str, int]] = {}
    for i in range(len(inputs)):
        entry = inputs[i]
        input_str = entry["input"]
        output = entry["output"]
        with open(MUTATION_BRIDGE_FILE_PATH, 'w') as f:
            json.dump({"ORIGINAL_SENTENCE": original_sentence, "MUTATED_SENTENCE": input_str,
                       "EXPECTED_OUTPUT": output}, f)
        handle_exec_inprocess(COSMIC_RAY_CONFIG, COSMIC_RAY_SESSION)
        kill_count = get_mutation_kill_count_from_db()
        sut_error_kill_count = get_sut_error_results()
        result[input_str] = {"kill_count": kill_count, "sut_error_kill_count": sut_error_kill_count}
        print(f"Input {i + 1}/{len(inputs)}: killed {kill_count} mutants")
        clear_work_results()
        reset_sut_source_code()
    return result


def sample_eval_inputs(corpus_result_mapping, number_of_samples):
    sampled: list[dict[str, Any]] = []
    for i in range(number_of_samples):
        chosen = random.choice(corpus_result_mapping)
        while (chosen in sampled):
            chosen = random.choice(corpus_result_mapping)
        sampled.append(chosen)
    return sampled
    

def get_mutant_count():
    conn = sqlite3.connect(COSMIC_RAY_SESSION)
    cursor = conn.cursor()
    cursor.execute("SELECT count(*) FROM mutation_specs")
    result = int(cursor.fetchone()[0])
    conn.close()
    return result


def clear_work_results():
    conn = sqlite3.connect(COSMIC_RAY_SESSION)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM work_results")
    conn.commit()
    conn.close()


def get_mutation_kill_count_from_db():
    conn = sqlite3.connect(COSMIC_RAY_SESSION)
    cursor = conn.cursor()
    cursor.execute("SELECT count(*) FROM work_results WHERE test_outcome = 'KILLED'")
    result = int(cursor.fetchone()[0])
    conn.close()
    return result


def get_sut_error_results():
    conn = sqlite3.connect(COSMIC_RAY_SESSION)
    cursor = conn.cursor()
    cursor.execute("""
                   SELECT count(*)
                   FROM work_results
                   WHERE test_outcome = 'KILLED' AND output NOT LIKE '%SUT return value:%' AND output != 'timeout'
                   """)
    result = int(cursor.fetchone()[0])
    conn.close()
    return result


if __name__ == '__main__':
    main(sys.argv)
