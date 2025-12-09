"Support for running tests in a subprocess."
import _thread
import importlib
import logging
import os
import re
import shlex
import subprocess
import sys
import threading
import traceback
from io import StringIO

from cosmic_ray.work_item import TestOutcome

log = logging.getLogger(__name__)

ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')


# We use an asyncio-subprocess-based approach here instead of a simple
# subprocess.run()-based approach because there are problems with timeouts and
# reading from stderr in subprocess.run. Since we have to be prepared for test
# processes that run longer than timeout (and, indeed, which run forever), the
# broken subprocess stuff simply doesn't work. So we do this, which seems to
# work on all platforms.


def run_tests(command, timeout):
    """Run test command in a subprocess.

    If the command exits with status 0, then we assume that all tests passed. If
    it exits with any other code, we assume a test failed. If the call to launch
    the subprocess throws an exception, we consider the test 'incompetent'.

    Tests which time out are considered 'killed' as well.

    Args:
        command (str): The command to execute.
        timeout (number): The maximum number of seconds to allow the tests to run.

    Return: A tuple `(TestOutcome, output)` where the `output` is a string
        containing the output of the command.
    """
    log.info("Running test (timeout=%s): %s", timeout, command)

    # We want to avoid writing pyc files in case our changes happen too fast for Python to
    # notice them. If the timestamps between two changes are too small, Python won't recompile
    # the source.
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"

    try:
        proc = subprocess.run(shlex.split(command), check=True, env=env, timeout=timeout, capture_output=True)
        assert proc.returncode == 0
        return (TestOutcome.SURVIVED, proc.stdout.decode("utf-8"))

    except subprocess.CalledProcessError as err:
        return (TestOutcome.KILLED, err.output.decode("utf-8"))

    except subprocess.TimeoutExpired:
        return (TestOutcome.KILLED, "timeout")

    except Exception:  # pylint: disable=W0703
        return (TestOutcome.INCOMPETENT, traceback.format_exc())


def run_tests_inprocess(sut_module_name, test_module_name, test_function_name, timeout):
    log.info("Running test %s (timeout=%s)", test_module_name + "." + test_function_name, timeout)
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    old_stdout = sys.stdout
    old_stderr = sys.stderr
    sys.stdout = StringIO()
    sys.stderr = StringIO()
    timed_out = [False]

    def timeout_handler():
        timed_out[0] = True
        _thread.interrupt_main()

    timer = threading.Timer(timeout, timeout_handler)
    timer.daemon = True
    timer.start()
    try:
        sut_module = importlib.import_module(sut_module_name)
        importlib.reload(sut_module)
        test_module = importlib.import_module(test_module_name)
        test_function = getattr(test_module, test_function_name)
        test_function()
        timer.cancel()
        output = sys.stdout.getvalue() + sys.stderr.getvalue()
        return (TestOutcome.SURVIVED, ansi_escape.sub('', output))
    except KeyboardInterrupt:
        timer.cancel()
        if timed_out[0]:
            return (TestOutcome.KILLED, "timeout")
        raise
    except Exception:
        timer.cancel()
        output = sys.stdout.getvalue() + sys.stderr.getvalue() + traceback.format_exc()
        return (TestOutcome.KILLED, ansi_escape.sub('', output))
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr
