"""Static analysis: string extraction, IOC harvesting, rule matching, scoring.

Every module in here reads from an :class:`~rea.core.model.Artifact` and adds
findings, indicators or statistics to it. They are independent so a caller can
run any subset (useful when triaging tens of thousands of samples).
"""
