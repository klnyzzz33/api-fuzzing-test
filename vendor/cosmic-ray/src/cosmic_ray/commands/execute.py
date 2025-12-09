"Implementation of the 'execute' command."

import logging
import os

from cosmic_ray.config import ConfigDict
from cosmic_ray.mutating import mutate_and_test_inprocess
from cosmic_ray.plugins import get_distributor
from cosmic_ray.progress import reports_progress

log = logging.getLogger(__name__)

_progress_messages = {}  # pylint: disable=invalid-name


def _update_progress(work_db):
    num_work_items = work_db.num_work_items
    pending = num_work_items - work_db.num_results
    total = num_work_items
    remaining = total - pending
    message = f"{remaining} out of {total} completed"
    _progress_messages[work_db.name] = message


def _report_progress(stream):
    for db_name, progress_message in _progress_messages.items():
        session = os.path.splitext(db_name)[0]
        print(f"{session} : {progress_message}", file=stream)


@reports_progress(_report_progress)
def execute(work_db, config: ConfigDict):
    """Execute any pending work in the database `work_db`,
    recording the results.

    This looks for any work in `work_db` which has no results, schedules it to
    be executed, and records any results that arrive.
    """
    _update_progress(work_db)
    distributor = get_distributor(config.distributor_name)

    def on_task_complete(job_id, work_result):
        work_db.set_result(job_id, work_result)
        _update_progress(work_db)
        log.info("Job %s complete", job_id)

    log.info("Beginning execution")
    distributor(
        work_db.pending_work_items,
        config.test_command,
        config.timeout,
        config.distributor_config,
        on_task_complete=on_task_complete,
    )
    log.info("Execution finished")


def execute_batch(work_db, config: ConfigDict):
    """Execute batch size of pending work in the database `work_db`,
    recording the results.

    This looks for any work in `work_db` which has no results, schedules it to
    be executed, and records any results that arrive.
    """
    _update_progress(work_db)
    distributor = get_distributor(config.distributor_name)

    def on_task_complete(job_id, work_result):
        work_db.set_result(job_id, work_result)
        _update_progress(work_db)
        log.info("Job %s complete", job_id)

    log.info("Beginning execution")
    distributor(
        work_db.pending_work_items_batch,
        config.test_command,
        config.timeout,
        config.distributor_config,
        on_task_complete=on_task_complete,
    )
    log.info("Execution finished")


def execute_inprocess(work_db, config: ConfigDict):
    _update_progress(work_db)

    log.info("Beginning execution")

    pending_work = work_db.pending_work_items
    for work_item in pending_work:
        result = mutate_and_test_inprocess(
            mutations=work_item.mutations,
            sut_module_name=config.module_name,
            test_module_name=config.test_module_name,
            test_function_name=config.test_function_name,
            timeout=config.timeout
        )
        work_db.set_result(work_item.job_id, result)
        _update_progress(work_db)
        log.info("Job %s complete", work_item.job_id)

    log.info("Execution finished")


def execute_inprocess_batch(work_db, config: ConfigDict):
    _update_progress(work_db)

    log.info("Beginning execution")

    pending_work = work_db.pending_work_items_batch
    for work_item in pending_work:
        result = mutate_and_test_inprocess(
            mutations=work_item.mutations,
            sut_module_name=config.module_name,
            test_module_name=config.test_module_name,
            test_function_name=config.test_function_name,
            timeout=config.timeout
        )
        work_db.set_result(work_item.job_id, result)
        _update_progress(work_db)
        log.info("Job %s complete", work_item.job_id)

    log.info("Execution finished")
