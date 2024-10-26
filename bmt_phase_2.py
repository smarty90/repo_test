"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'add_comment_1' block
    add_comment_1(container=container)

    return

@phantom.playbook_block()
def send_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("send_email_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    body_formatted_string = phantom.format(
        container=container,
        template="""{0} 발생.\n심각도 : {2}\n발생 시각 : {1}\n""",
        parameters=[
            "container:name",
            "container:create_time",
            "container:severity",
            ""
        ])
    subject_formatted_string = phantom.format(
        container=container,
        template="""SOAR 이벤트 발생 안내\n""",
        parameters=[])

    name_value = container.get("name", None)
    create_time_value = container.get("create_time", None)
    severity_value = container.get("severity", None)

    parameters = []

    if body_formatted_string is not None:
        parameters.append({
            "to": "michael.kim@wiredcorp.co.kr",
            "body": body_formatted_string,
            "from": "smarty90@naver.com",
            "subject": subject_formatted_string,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("send email", parameters=parameters, name="send_email_1", assets=["smtp_naver"])

    return


@phantom.playbook_block()
def add_comment_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_comment_1() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="phase 2 start")

    send_email_1(container=container)

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