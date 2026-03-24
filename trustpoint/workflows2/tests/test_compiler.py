# workflows2/tests/test_compiler.py
from __future__ import annotations

from django.test import SimpleTestCase

from workflows2.compiler.compiler import compile_workflow_yaml
from workflows2.compiler.errors import CompileError


VALID_YAML = """\
schema: trustpoint.workflow.v2
name: Example v2
enabled: true

trigger:
  on: device.created
  sources:
    trustpoint: true
    ca_ids: []
    domain_ids: []
    device_ids: []

apply:
  - exists: ${event.device}

workflow:
  start: notify

  steps:
    notify:
      type: email
      title: Send email
      to: [test.test@gmx.de]
      subject: "New device: ${event.device.common_name}"
      body: |
        Common Name: ${event.device.common_name}
        Full event: ${json(event)}

    call_status:
      type: webhook
      method: POST
      url: https://example.com/status
      body:
        nested:
          msg: "Hello ${upper(event.device.common_name)}"
          list:
            - "A ${event.device.common_name}"
            - "B ${json(vars)}"
      capture:
        vars.http_status: status_code

    route_by_status:
      type: logic
      cases:
        - when:
            compare:
              left: ${vars.http_status}
              op: "=="
              right: 200
          outcome: ok
      default: fail

    stop_ok:
      type: set
      vars: {}

    stop_fail:
      type: set
      vars: {}

  flow:
    - from: notify
      to: call_status
    - from: call_status
      to: route_by_status
    - from: route_by_status
      on: ok
      to: stop_ok
    - from: route_by_status
      on: fail
      to: stop_fail
"""


class CompilerTests(SimpleTestCase):
    def test_compile_valid(self) -> None:
        ir = compile_workflow_yaml(VALID_YAML, compiler_version="test")
        self.assertEqual(ir["ir_version"], "v2")
        self.assertEqual(ir["trigger"]["on"], "device.created")
        self.assertTrue(ir["meta"]["source_hash"])
        self.assertTrue(ir["meta"]["ir_hash"])

    def test_yaml_key_on_is_not_boolean(self) -> None:
        ir = compile_workflow_yaml(VALID_YAML, compiler_version="test")
        self.assertEqual(ir["trigger"]["on"], "device.created")

    def test_root_refs_allowed(self) -> None:
        ir = compile_workflow_yaml(VALID_YAML, compiler_version="test")
        body = ir["workflow"]["steps"]["notify"]["params"]["body"]
        self.assertIsInstance(body, dict)
        self.assertEqual(body["kind"], "template")

    def test_templates_deep_in_webhook_body(self) -> None:
        ir = compile_workflow_yaml(VALID_YAML, compiler_version="test")
        body = ir["workflow"]["steps"]["call_status"]["params"]["body"]
        self.assertIsInstance(body, dict)
        self.assertIn("nested", body)
        self.assertIsInstance(body["nested"]["msg"], dict)
        self.assertEqual(body["nested"]["msg"]["kind"], "template")

    def test_missing_outcome_mapping_errors(self) -> None:
        bad = VALID_YAML.replace(
            "    - from: route_by_status\n      on: fail\n      to: stop_fail\n",
            "",
        )
        with self.assertRaises(CompileError):
            compile_workflow_yaml(bad, compiler_version="test")

    def test_unknown_flow_to_is_error(self) -> None:
        bad = VALID_YAML + "\n    - from: stop_ok\n      to: does_not_exist\n"
        with self.assertRaises(CompileError):
            compile_workflow_yaml(bad, compiler_version="test")

    def test_unknown_top_level_key(self) -> None:
        bad = VALID_YAML.replace("enabled: true", "enabled: true\nfoo: 1")
        with self.assertRaises(CompileError) as ctx:
            compile_workflow_yaml(bad, compiler_version="test")
        self.assertIn("Unknown key", str(ctx.exception))
        self.assertIn("foo", str(ctx.exception))

    def test_unknown_step_key_with_suggestion(self) -> None:
        bad = VALID_YAML.replace('subject: "New device:', 'subjectt: "New device:')
        with self.assertRaises(CompileError) as ctx:
            compile_workflow_yaml(bad, compiler_version="test")
        s = str(ctx.exception)
        self.assertIn("subjectt", s)
        self.assertIn("Did you mean", s)

    def test_unknown_webhook_capture_key(self) -> None:
        bad = VALID_YAML.replace("vars.http_status: status_code", "statuz_code: status_code")
        with self.assertRaises(CompileError):
            compile_workflow_yaml(bad, compiler_version="test")

    def test_unknown_step_type_has_good_error(self) -> None:
        bad = VALID_YAML.replace("type: set", "type: seta", 1)
        with self.assertRaises(CompileError) as ctx:
            compile_workflow_yaml(bad, compiler_version="test")
        s = str(ctx.exception)
        self.assertIn("Unknown step type", s)
        self.assertIn("seta", s)

    def test_compute_step_compiles_expr_assignments(self) -> None:
        yaml_text = VALID_YAML.replace(
            "stop_ok:",
            """compute_stuff:
      type: compute
      set:
        vars.total: ${add(vars.http_status, 10)}
        vars.upper_name: ${upper(event.device.common_name)}

    stop_ok:
""",
        )

        yaml_text = yaml_text.replace(
            "    - from: route_by_status\n      on: ok\n      to: stop_ok\n",
            "    - from: route_by_status\n      on: ok\n      to: compute_stuff\n"
            "    - from: compute_stuff\n      to: stop_ok\n",
        )

        ir = compile_workflow_yaml(yaml_text, compiler_version="test")
        step = ir["workflow"]["steps"]["compute_stuff"]
        self.assertEqual(step["type"], "compute")

        set_map = step["params"]["set"]
        self.assertIn("vars.total", set_map)
        self.assertEqual(set_map["vars.total"]["kind"], "expr")
        self.assertEqual(set_map["vars.total"]["expr"]["kind"], "call")
        self.assertEqual(set_map["vars.total"]["expr"]["name"], "add")

    def test_compute_requires_single_expr_string(self) -> None:
        yaml_text = VALID_YAML.replace(
            "stop_ok:",
            """compute_stuff:
      type: compute
      set:
        vars.total: "Total is ${add(vars.http_status, 10)}"

    stop_ok:
""",
        )
        yaml_text = yaml_text.replace(
            "    - from: route_by_status\n      on: ok\n      to: stop_ok\n",
            "    - from: route_by_status\n      on: ok\n      to: compute_stuff\n"
            "    - from: compute_stuff\n      to: stop_ok\n",
        )

        with self.assertRaises(CompileError):
            compile_workflow_yaml(yaml_text, compiler_version="test")

    def test_compute_disallows_non_vars_targets(self) -> None:
        yaml_text = VALID_YAML.replace(
            "stop_ok:",
            """compute_stuff:
      type: compute
      set:
        event.bad: ${add(1, 2)}

    stop_ok:
""",
        )
        yaml_text = yaml_text.replace(
            "    - from: route_by_status\n      on: ok\n      to: stop_ok\n",
            "    - from: route_by_status\n      on: ok\n      to: compute_stuff\n"
            "    - from: compute_stuff\n      to: stop_ok\n",
        )

        with self.assertRaises(CompileError):
            compile_workflow_yaml(yaml_text, compiler_version="test")

    def test_set_accepts_vars_prefixed_keys_and_normalizes_ir(self) -> None:
        yaml_text = VALID_YAML.replace(
            "    stop_ok:\n      type: set\n      vars: {}\n",
            """    stop_ok:
      type: set
      vars:
        vars.result: ok
        vars.message: Status was ${vars.http_status}
""",
        )

        ir = compile_workflow_yaml(yaml_text, compiler_version="test")
        vars_map = ir["workflow"]["steps"]["stop_ok"]["params"]["vars"]
        self.assertEqual(vars_map["result"], "ok")
        self.assertEqual(vars_map["message"]["kind"], "template")

    def test_expr_disallows_unknown_function(self) -> None:
        yaml_text = VALID_YAML.replace(
            "stop_ok:",
            """compute_stuff:
      type: compute
      set:
        vars.total: ${eval("1+1")}

    stop_ok:
""",
        )
        yaml_text = yaml_text.replace(
            "    - from: route_by_status\n      on: ok\n      to: stop_ok\n",
            "    - from: route_by_status\n      on: ok\n      to: compute_stuff\n"
            "    - from: compute_stuff\n      to: stop_ok\n",
        )

        with self.assertRaises(CompileError):
            compile_workflow_yaml(yaml_text, compiler_version="test")

    def test_expr_error_explains_nested_template_refs(self) -> None:
        yaml_text = VALID_YAML.replace(
            "${vars.http_status}",
            "${str(${vars.http_status})}",
            1,
        )

        with self.assertRaises(CompileError) as ctx:
            compile_workflow_yaml(yaml_text, compiler_version="test")

        self.assertIn("Expressions already live inside ${...}", str(ctx.exception))

    def test_allows_implicit_end_for_non_outcome_step(self) -> None:
        yaml_text = """\
schema: trustpoint.workflow.v2
name: Implicit end
enabled: true

trigger:
  on: device.created
  sources:
    trustpoint: true

workflow:
  start: a
  steps:
    a:
      type: set
      vars: {}
    b:
      type: set
      vars: {}
  flow:
    - from: a
      to: b
"""
        ir = compile_workflow_yaml(yaml_text, compiler_version="test")
        self.assertIn("b", ir["workflow"]["steps"])
        # b has no outgoing transition -> allowed
        self.assertNotIn("b", ir["workflow"]["transitions"])

    def test_unreachable_step_is_error(self) -> None:
        yaml_text = """\
schema: trustpoint.workflow.v2
name: Unreachable step
enabled: true

trigger:
  on: device.created
  sources:
    trustpoint: true

workflow:
  start: a
  steps:
    a:
      type: set
      vars: {}
    b:
      type: set
      vars: {}
    c:
      type: set
      vars: {}
  flow:
    - from: a
      to: b
"""

        with self.assertRaises(CompileError) as ctx:
            compile_workflow_yaml(yaml_text, compiler_version="test")

        self.assertIn('Unreachable steps', str(ctx.exception))
        self.assertIn('c', str(ctx.exception))

    def test_branch_only_var_is_rejected_at_merge(self) -> None:
        yaml_text = """\
schema: trustpoint.workflow.v2
name: Branch var
enabled: true

trigger:
  on: device.created
  sources:
    trustpoint: true

workflow:
  start: fetch
  steps:
    fetch:
      type: webhook
      method: POST
      url: https://example.com/status
      capture:
        vars.http_status: status_code
    choose:
      type: logic
      cases:
        - when:
            compare:
              left: ${vars.http_status}
              op: "=="
              right: 200
          outcome: left
      default: right
    left_only:
      type: set
      vars:
        token: abc
    right_only:
      type: set
      vars: {}
    merged_email:
      type: email
      to: [ops@example.com]
      subject: "Token ${vars.token}"
      body: "Status ${vars.http_status}"
  flow:
    - from: fetch
      to: choose
    - from: choose
      on: left
      to: left_only
    - from: choose
      on: right
      to: right_only
    - from: left_only
      to: merged_email
    - from: right_only
      to: merged_email
"""

        with self.assertRaises(CompileError) as ctx:
            compile_workflow_yaml(yaml_text, compiler_version="test")

        self.assertIn('vars.token', str(ctx.exception))
        self.assertIn('may not be initialized', str(ctx.exception))

    def test_set_step_cannot_reference_var_created_in_same_step(self) -> None:
        yaml_text = """\
schema: trustpoint.workflow.v2
name: Same set step
enabled: true

trigger:
  on: device.created
  sources:
    trustpoint: true

workflow:
  start: assign
  steps:
    assign:
      type: set
      vars:
        first: hello
        second: "${vars.first}"
  flow: []
"""

        with self.assertRaises(CompileError) as ctx:
            compile_workflow_yaml(yaml_text, compiler_version="test")

        self.assertIn('vars.first', str(ctx.exception))
        self.assertIn('assign', str(ctx.exception))

    def test_compute_step_allows_reference_to_prior_assignment_in_same_step(self) -> None:
        yaml_text = """\
schema: trustpoint.workflow.v2
name: Sequential compute
enabled: true

trigger:
  on: device.created
  sources:
    trustpoint: true

workflow:
  start: calc
  steps:
    calc:
      type: compute
      set:
        vars.base: ${add(1, 2)}
        vars.total: ${add(vars.base, 10)}
  flow: []
"""

        ir = compile_workflow_yaml(yaml_text, compiler_version="test")
        self.assertIn("calc", ir["workflow"]["steps"])
