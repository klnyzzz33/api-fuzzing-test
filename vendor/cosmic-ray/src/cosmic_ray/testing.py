"Support for running tests in a subprocess."
import importlib
import logging
import os
import re
import shlex
import signal
import subprocess
import traceback
import warnings

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


def run_tests_inprocess(module_paths_to_reload, test_module_name, test_function_name, timeout):
    log.info("Running test %s (timeout=%s)", test_module_name + "." + test_function_name, timeout)
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore",
            category=SyntaxWarning,
        )
        for mod_path in module_paths_to_reload:
            mod_name = mod_path.replace('/', '.').replace('\\', '.').replace('.py', '')
            sut_module = importlib.import_module(mod_name)
            importlib.reload(sut_module)
        test_module = importlib.import_module(test_module_name)
        test_function = getattr(test_module, test_function_name)

        def timeout_handler(signum, frame):
            raise TimeoutError("Test execution exceeded timeout")
        
        def reset_timeout():
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)

        old_handler = signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(int(timeout))
        try:
            result, error = test_function()
            reset_timeout()
            if error:
                return (TestOutcome.KILLED, ansi_escape.sub('', f"{result}\n\n{error}"))
            return (TestOutcome.SURVIVED, ansi_escape.sub('', result))
        except TimeoutError:
            reset_timeout()
            return (TestOutcome.KILLED, "timeout")
        except Exception:
            reset_timeout()
            return (TestOutcome.KILLED, ansi_escape.sub('', traceback.format_exc()))
