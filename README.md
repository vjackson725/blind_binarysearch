# Overview

This is a script to automate Blind SQL Injection.

Given a known injection, this script will automatically work out the value of whatever string you wish to acquire.


# Requirements

Python [`requests`](http://docs.python-requests.org/en/master/) library.
Install using `pip install requests`.

# Usage

There are Four parameters:
* target: The target as a url. This must specify the protocol, i.e. `https://...`.
* param: The injectible parameter. We assume this is a GET parameter.
* base-query: The base SQL statement to use. Usually of the form `... AND {} OR SLEEP(1) OR ...`. Use the usual python format-string format (i.e. `{}`) to denote where you want the conditional to go.
* var: The variable you want to test. e.g. `USER()`


# TODO

Possible improvements are:
* Detecting the Type, and picking a suitable injection, so we aren't limited to just strings.
* Clean it up a bit more; the code is not DRY.
* Add a timeout between requests so we don't spam the server!
* Support for POST and Cookie parameters
