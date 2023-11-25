"""
Module detecting hardcoded APIs.

References: 
1. https://github.com/crytic/slither/pull/2015/files
2. https://github.com/Skyscanner/sonar-secrets/blob/master/java/src/main/java/org/sonar/skyscanner/java/checks/APIKeys.java
3. https://www.geeksforgeeks.org/pattern-matching-python-regex/
4. https://github.com/arjunsuvarna1/CSE6324_Team4_Fall23/blob/main/Detectors/ecrecover/ecrecover.py
5. AWS Key and Bitly regular expression - https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=7180102&tag=1
"""
from typing import DefaultDict, List, Tuple
from slither.utils.output import Output
from slither.core.cfg.node import Node
from slither.core.declarations.function import Function
from slither.core.variables.local_variable import LocalVariable
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
import re


class ApiKey(AbstractDetector):
    """
    Detect hardcoded API keys
    """

    ARGUMENT = "apikey"
    HELP = "API key is hardcoded"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW

    WIKI = "https://github.com/crytic/slither/wiki/Detector-Documentation"
    WIKI_TITLE = "APIKEY"
    WIKI_DESCRIPTION = "APIKEY"
    WIKI_EXPLOIT_SCENARIO = """
  
"""
    WIKI_RECOMMENDATION = (
        "Check the for hardcoded API key"
    )

    def _detect(self) -> List[Output]:
        results = []

        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions_and_modifiers_declared:
                var_results = _detect_apikey(function)
                if var_results:
                    info: DETECTOR_INFO = [
                        function,
                        "\n has hardcoded API key ",
                        ":\n",
                    ]
                    for node in var_results:
                        info += ["\t\t- ", node, "\n"]
                    res = self.generate_result(info)
                    results.append(res)

        return results

def _detect_apikey(function: Function,) -> List[Tuple[Function, DefaultDict[LocalVariable, List[Node]]]]:
    results = []

    for node in function.nodes:
        for ir in node.irs:
            expression = str(ir.expression)
            # Regular expressions used:
            # 1. Sonar qube
            # 2. AWS Client ID format
            # 3. AWS Secret key format
            # 4. Bitly Client ID format
            # 5. Bitly Secret key format
            if re.compile('(api|gitlab|github|slack|google|aws|jenkins)_?(key|token|secret|auth)?'
                    ).search(expression) or re.compile(
                    'AKIA[0-9A-Z]{16}').search(expression) or re.compile(
                    '[0-9a-zA-Z/+]{40}').search(expression)or re.compile(
                    '[0-9a-zA-Z_]{5,31}').search(expression) or re.compile(
                    'R_[0-9a-f]{32}').search(expression):
                results.append(node)
            
    return (results) 