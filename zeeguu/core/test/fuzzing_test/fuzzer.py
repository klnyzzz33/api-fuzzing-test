from fuzzingbook.Grammars import URL_GRAMMAR
from fuzzingbook.Grammars import simple_grammar_fuzzer as fuzz

from zeeguu.core.model.url import Url
from zeeguu.core.model.url_keyword import UrlKeyword
from zeeguu.core.nlp_pipeline import SPACY_EN_MODEL
from zeeguu.core.nlp_pipeline.automatic_gec_tagging import AutoGECTagging
from zeeguu.core.test.fuzzing_test.setup import test_env


def test_url_fuzzing(test_env):
    for i in range(10):
        generated_url = fuzz(grammar=URL_GRAMMAR)
        url_obj = Url(url=generated_url)
        results = UrlKeyword.get_url_keywords_from_url(url_obj)
        print(results)


def test_gec_tagging_labels(test_env):
    agt = AutoGECTagging(SPACY_EN_MODEL, 'en')
    d = [{"word": "Cats", "isInSentence": True},
         {"word": "are", "isInSentence": True},
         {"word": "amzaing", "isInSentence": True}]
    print(agt.anottate_clues(d, original_sentence="Cats are amazing."))
