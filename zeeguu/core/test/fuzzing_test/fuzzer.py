import pytest
from fuzzingbook.Grammars import simple_grammar_fuzzer as fuzz
from fuzzingbook.Grammars import URL_GRAMMAR

from zeeguu.core.test.fuzzing_test.setup import test_env
from zeeguu.core.model.url import Url
from zeeguu.core.model.url_keyword import UrlKeyword
from zeeguu.core.nlp_pipeline.automatic_gec_tagging import AutoGECTagging

def test_url_fuzzing(test_env):
    for i in range(10):
        generated_url = fuzz(grammar=URL_GRAMMAR)
        url_obj = Url(url=generated_url)
        results = UrlKeyword.get_url_keywords_from_url(url_obj)
        print(results)

def test_gec_tagging_labels(test_env):
    agt = AutoGECTagging()
    for i in range(10):
        AutoGECTagging.anottate_clues(word_dictionary_list=[], original_sentence="")

if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
