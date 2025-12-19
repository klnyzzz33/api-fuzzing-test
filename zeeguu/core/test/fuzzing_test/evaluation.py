import json
import os
import sqlite3
import sys
from dataclasses import dataclass, asdict

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
    mutants_killed: int
    mutation_score: float

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
            f"Mutation score: {self.mutation_score * 100:.2f}%\n"
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
        kill_count = run_eval(test_result.original_sentence, test_result.corpus_result_mapping, mutant_count)
        eval_result = EvalResult(file=result_file_name,
                                 original_sentence=test_result.original_sentence,
                                 corpus_size=len(test_result.corpus_result_mapping),
                                 coverage_size=len(test_result.coverage),
                                 mutants_killed=kill_count,
                                 mutation_score=kill_count / mutant_count)
        eval_result.to_json(eval_file_name)
        print(eval_result)
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
        print(f"Input {i + 1}/{len(corpus_result_mapping)}: Killed {new_kills} mutants, {mutant_count - kills_before - new_kills} remaining")
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
