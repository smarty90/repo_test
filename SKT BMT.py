"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'playbook_bmt_phase_1_1' block
    playbook_bmt_phase_1_1(container=container)

    return

@phantom.playbook_block()
def playbook_bmt_phase_1_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook_bmt_phase_1_1() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "repo_test/bmt_phase_1", returns the playbook_run_id
    playbook_run_id = phantom.playbook("repo_test/bmt_phase_1", container=container, name="playbook_bmt_phase_1_1", callback=playbook_bmt_phase_2_1)

    return


@phantom.playbook_block()
def playbook_bmt_phase_2_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook_bmt_phase_2_1() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "repo_test/bmt_phase_2", returns the playbook_run_id
    playbook_run_id = phantom.playbook("repo_test/bmt_phase_2", container=container)

    playbook_bmt_phase_3_1(container=container)

    return


@phantom.playbook_block()
def playbook_bmt_phase_3_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("playbook_bmt_phase_3_1() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "repo_test/bmt_phase_3", returns the playbook_run_id
    playbook_run_id = phantom.playbook("repo_test/bmt_phase_3", container=container)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return