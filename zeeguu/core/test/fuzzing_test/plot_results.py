import os

import numpy as np
from matplotlib import pyplot as plt

from zeeguu.core.test.fuzzing_test.evaluation import EvalResult


def main():
    result_dir = "zeeguu/core/test/fuzzing_test/final_results"
    test_results = {"unguided": [], "coverage-guided": [], "mutation-guided": []}
    for path in os.listdir(result_dir):
        test_result = EvalResult.from_json(f"{result_dir}/{path}")
        for key in test_results.keys():
            if key in path:
                test_results[key].append(test_result)
    statistics = calculate_statistics(test_results)
    for method, stat in statistics.items():
        print(f"{method}: average kill count = {stat['kill_count_average']:.2f}")
        print(f"{method}: average coverage = {stat['coverage_average']:.2f}")
    plot_results(statistics)


def calculate_statistics(test_results):
    statistics = {}
    for method, results in test_results.items():
        total_kills = 0
        total_coverage = 0
        kill_count_distribution = []
        coverage_distribution = []
        for result in results:
            for kill_count_values in result.mutants_killed.values():
                kill_count_value = kill_count_values["kill_count"]
                total_kills += kill_count_value
                kill_count_distribution.append(kill_count_value)
            coverage_value = result.coverage_size
            total_coverage += coverage_value
            coverage_distribution.append(coverage_value)
        statistics[method] = {
            "kill_count_average": (
                total_kills / len(kill_count_distribution) if len(kill_count_distribution) > 0 else 0.0
            ),
            "coverage_average": (
                total_coverage / len(coverage_distribution) if len(coverage_distribution) > 0 else 0.0
            ),
            "kill_count_distribution": kill_count_distribution,
            "coverage_distribution": coverage_distribution
        }
    return statistics


def plot_results(statistics):
    methods = list(statistics.keys())
    coverage_averages = [statistics[m]["coverage_average"] for m in methods]
    kill_count_averages = [statistics[m]["kill_count_average"] for m in methods]
    kill_count_distribution = [statistics[m]["kill_count_distribution"] for m in methods]
    coverage_distribution = [statistics[m]["coverage_distribution"] for m in methods]
    cmap = plt.get_cmap("Blues")
    colors = cmap(np.linspace(0.4, 1, len(methods)))
    fig1, (ax1, ax2) = plt.subplots(1, 2, figsize=(12.5, 5))
    b1 = ax1.bar(methods, coverage_averages, color=colors)
    ax1.set_title("Average coverage per method")
    ax1.set_xlabel("Method")
    ax1.set_ylabel("Average coverage")
    ax1.bar_label(b1, fmt="%.2f", padding=3)
    b2 = ax2.bar(methods, kill_count_averages, color=colors)
    ax2.set_title("Average mutation score per method")
    ax2.set_xlabel("Method")
    ax2.set_ylabel("Average mutation score")
    ax2.bar_label(b2, fmt="%.2f", padding=3)
    fig1.tight_layout()
    fig2, (ax3, ax4) = plt.subplots(1, 2, figsize=(12.5, 5))
    bp1 = ax3.boxplot(coverage_distribution, labels=methods, patch_artist=True)
    for patch, color in zip(bp1["boxes"], colors):
        patch.set_facecolor(color)
    ax3.set_title("Coverage distribution")
    ax3.set_xlabel("Method")
    ax3.set_ylabel("Coverage")
    bp2 = ax4.boxplot(kill_count_distribution, labels=methods, patch_artist=True)
    for patch, color in zip(bp2["boxes"], colors):
        patch.set_facecolor(color)
    ax4.set_title("Mutation score distribution")
    ax4.set_xlabel("Method")
    ax4.set_ylabel("Kill count")
    fig2.tight_layout()
    plt.show()


if __name__ == "__main__":
    main()
