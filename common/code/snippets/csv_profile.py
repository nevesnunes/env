#!/usr/bin/env python3

from pandas_profiling import ProfileReport
import pandas as pd

df = pd.read_csv("/foo")
profile = ProfileReport(df, title="Pandas Profiling Report")
