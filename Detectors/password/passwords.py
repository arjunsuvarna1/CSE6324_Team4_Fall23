"""
Module detecting hardcoded APIs.

References:
1. https://github.com/crytic/slither/pull/2015/files   (Detector structure) Author: tuturu-tech - https://github.com/tuturu-tech
2. https://github.com/Skyscanner/sonar-secrets/blob/master/java/src/main/java/org/sonar/skyscanner/java/checks/Passwords.java

"""
import re
from typing import DefaultDict, List, Tuple

from slither.core.cfg.node import Node
from slither.core.declarations.function import Function
from slither.core.variables.local_variable import LocalVariable
from slither.detectors.abstract_detector import (DETECTOR_INFO,
                                                 AbstractDetector,
                                                 DetectorClassification)
from slither.utils.output import Output


class Password(AbstractDetector):
    """
    Detect hardcoded password
    """

    ARGUMENT = "passwords"
    HELP = "Password is hardcoded"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW

    WIKI = "https://github.com/crytic/slither/wiki/Detector-Documentation"
    WIKI_TITLE = "PASSWORDS"
    WIKI_DESCRIPTION = "PASSWORDS"
    WIKI_EXPLOIT_SCENARIO = """
  
"""
    WIKI_RECOMMENDATION = (
        "Check for hardcoded password"
    )

    def _detect(self) -> List[Output]:
        results = []

        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions_and_modifiers_declared:
                var_results = _detect_password(function)
                if var_results:
                    info: DETECTOR_INFO = [
                        function,
                        "\n has hardcoded password ",
                        ":\n",
                    ]
                    for node in var_results:
                        info += ["\t\t- ", node, "\n"]
                    res = self.generate_result(info)
                    results.append(res)

        return results

def _detect_password(function: Function,) -> List[Tuple[Function, DefaultDict[LocalVariable, List[Node]]]]:
    results = []

    password_pattern = re.compile(r'(password|passwd|pass|pwd|key)', re.IGNORECASE)

    for node in function.nodes:
        for ir in node.irs:
            expression = str(ir.expression)

            if password_pattern.search(expression):
                results.append(node)
            
    return (results) 