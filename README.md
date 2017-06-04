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

# Limitations

* We only consider the ASCII alphabet, excluding null.
* We only consider string lengths from 0 to 1000.
* We use ANSI escape codes to give a live display.
* We are limited to injection on strings (at the moment).
* We are limited to GET parameters.

# TODO

Possible improvements are:
* Clean it up a bit more; the code is not DRY.
* Add a timeout between requests so we don't spam the server!
* Detecting the Type, and picking a suitable injection, so we aren't limited to just strings.
* Support for POST and Cookie parameters
