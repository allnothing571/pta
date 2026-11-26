"""多项目 HTTP 层：项目解析、列表、新建、交付、任务列表、静态页。"""
import json
import os
import shutil
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request

from pta import targets
from pta.api import make_server
from pta.projects import ProjectBook
from pta.scope import Scope
from pta.transport import MockTransport
from pta.workspace import init_workspace, open_workspace


class ApiProjectsCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pta-apiproj-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self._old_home = os.environ.get("PTA_HOME")
        os.environ["PTA_HOME"] = os.path.join(self.tmp, "home")
        self.addCleanup(self._restore_home)

    def _restore_home(self):
        if self._old_home is None:
            os.environ.pop("PTA_HOME", None)
        else:
            os.environ["PTA_HOME"] = self._old_home

    def mk(self, alias, eng=None):
        root = os.path.join(self.tmp, "ws-" + alias)
        init_workspace(root, Scope(engagement_id=eng or ("ENG-" + alias.upper()),
                                   domains=("app.test",), allow_private=True,
                                   rate_per_host=1000.0, max_requests=5000,
                                   allowed_ports=(80, 443)))
        ws = open_workspace(root, transport=MockTransport([]))
        ws.vault.put("cred/A/authorization", "Bearer T")
        ws.store.close()
        targets.register(root, engagement_id=eng or ("ENG-" + alias.upper()),
                         domains=("app.test",), alias=alias, name=alias)
        return root

    def start(self):
        httpd, _bus = make_server(ProjectBook(), host="127.0.0.1", port=0)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.server_close)      # 先 close 再把线程收干净，否则每次留一个 listen socket
        self.addCleanup(httpd.shutdown)
        return httpd.server_port

    def call(self, port, path, payload=None, headers=None):
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        hdrs = dict(headers or {})
        if data is not None:
            hdrs["Content-Type"] = "application/json"
        req = urllib.request.Request("http://127.0.0.1:%d%s" % (port, path),
                                     data=data, headers=hdrs,
                                     method="POST" if data is not None else "GET")
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    def jcall(self, port, path, payload=None, headers=None):
        status, body = self.call(port, path, payload, headers)
        return status, json.loads(body.decode("utf-8"))


class RoutingTest(ApiProjectsCase):
    def test_empty_ledger_asks_which_project(self):
        port = self.start()
        status, body = self.jcall(port, "/api/state")
        self.assertEqual(status, 400)
        self.assertEqual(body["error"], "project_required")
        self.assertEqual(body["projects"], [])

    def test_single_project_is_selected_automatically(self):
        self.mk("solo")
        port = self.start()
        status, body = self.jcall(port, "/api/state")
        self.assertEqual(status, 200)
        self.assertEqual(body["project"]["alias"], "solo")
        self.assertEqual(body["engagement"], "ENG-SOLO")

    def test_header_picks_the_project(self):
        self.mk("one")
        self.mk("two")
        port = self.start()
        status, body = self.jcall(port, "/api/state")
        self.assertEqual(status, 400)                       # 两个项目就不猜了

        status, body = self.jcall(port, "/api/state", headers={"X-Pta-Project": "two"})
        self.assertEqual(status, 200)
        self.assertEqual(body["engagement"], "ENG-TWO")

        status, body = self.jcall(port, "/api/state?project=one")
        self.assertEqual(status, 200)
        self.assertEqual(body["engagement"], "ENG-ONE")

    def test_chinese_alias_survives_both_transports(self):
        """HTTP 头只吃 ISO-8859-1：中文别名要走 query，或者先转义再进头，两边都得认。"""
        self.mk("学院", eng="ENG-CN")
        self.mk("other")
        port = self.start()
        quoted = urllib.parse.quote("学院")

        status, body = self.jcall(port, "/api/state?project=" + quoted)
        self.assertEqual(status, 200)
        self.assertEqual(body["engagement"], "ENG-CN")

        status, body = self.jcall(port, "/api/state",
                                  headers={"X-Pta-Project": quoted})
        self.assertEqual(status, 200)
        self.assertEqual(body["engagement"], "ENG-CN")

        status, body = self.jcall(port, "/api/projects/" + quoted)
        self.assertEqual(status, 200)
        self.assertEqual(body["project"]["alias"], "学院")

    def test_unknown_project_404(self):
        self.mk("one")
        port = self.start()
        status, body = self.jcall(port, "/api/state", headers={"X-Pta-Project": "ghost"})
        self.assertEqual(status, 404)
        self.assertEqual(body["error"], "unknown_project")
        self.assertEqual(body["projects"], ["one"])


class ListingTest(ApiProjectsCase):
    def test_list_and_detail(self):
        self.mk("one")
        port = self.start()
        status, body = self.jcall(port, "/api/projects")
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 1)
        self.assertEqual(body["projects"][0]["alias"], "one")
        self.assertIn("stages", body)
        self.assertIn("workspaces", body)

        status, detail = self.jcall(port, "/api/projects/one")
        self.assertEqual(status, 200)
        self.assertIn("steps", detail)
        self.assertIn("next", detail)
        self.assertIn("why", detail)
        self.assertEqual(detail["stage"], "no_recon")       # 有身份、没证据

    def test_filters_pass_through(self):
        self.mk("one")
        port = self.start()
        status, body = self.jcall(port, "/api/projects?stage=no_recon")
        self.assertEqual(body["total"], 1)
        status, body = self.jcall(port, "/api/projects?stage=deliverable")
        self.assertEqual(body["total"], 0)
        status, body = self.jcall(port, "/api/projects?q=nomatch")
        self.assertEqual(body["total"], 0)


class CreateTest(ApiProjectsCase):
    def test_post_creates_then_conflicts(self):
        port = self.start()
        new_root = os.path.join(self.tmp, "made")
        status, body = self.jcall(port, "/api/projects",
                                  {"name": "新项目", "url": "http://app.test:8080/",
                                   "workspace": new_root})
        self.assertEqual(status, 201)
        self.assertFalse(body["created"].get("imported"))
        self.assertTrue(os.path.exists(os.path.join(new_root, "scope.json")))
        alias = body["project"]["alias"]

        status, body = self.jcall(port, "/api/projects",
                                  {"name": "再来", "url": "http://app.test/",
                                   "workspace": new_root})
        self.assertEqual(status, 409)
        self.assertEqual(body["error"], "already_exists")
        self.assertEqual(body["alias"], alias)

        status, body = self.jcall(port, "/api/projects")
        self.assertEqual(body["total"], 1)

    def test_bad_input_is_400(self):
        port = self.start()
        status, body = self.jcall(port, "/api/projects",
                                  {"name": "", "url": "http://app.test/",
                                   "workspace": os.path.join(self.tmp, "x")})
        self.assertEqual(status, 400)
        self.assertEqual(body["error"], "bad_name")

        status, body = self.jcall(port, "/api/projects",
                                  {"name": "x", "url": "http://app.test/",
                                   "workspace": "relative"})
        self.assertEqual(status, 400)
        self.assertEqual(body["error"], "bad_workspace")


class DeliverTest(ApiProjectsCase):
    def test_refuse_then_force_then_undo(self):
        self.mk("early")
        port = self.start()
        status, body = self.jcall(port, "/api/projects/early/deliver", {"delivered": True})
        self.assertEqual(status, 409)
        self.assertEqual(body["error"], "not_deliverable")
        self.assertEqual(body["stage"], "no_recon")
        self.assertIn("还没有任何证据", body["why"])

        status, body = self.jcall(port, "/api/projects/early/deliver",
                                  {"delivered": True, "force": True})
        self.assertEqual(status, 200)
        self.assertTrue(body["delivered"])

        status, body = self.jcall(port, "/api/projects/early")
        self.assertEqual(body["stage"], "delivered")

        status, body = self.jcall(port, "/api/projects/early/deliver", {"delivered": False})
        self.assertEqual(status, 200)
        status, body = self.jcall(port, "/api/projects/early")
        self.assertEqual(body["stage"], "no_recon")


class FixedModeTest(ApiProjectsCase):
    """`pta ui --workspace` / `serve(ws)`：绑死一个工作区时，列表和详情也得能打开。"""

    def start_fixed(self, root):
        ws = open_workspace(root, transport=MockTransport([]))
        self.addCleanup(ws.store.close)
        httpd, _bus = make_server(ProjectBook.single(ws), host="127.0.0.1", port=0)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)
        return httpd.server_port

    def test_unregistered_workspace_still_lists_and_opens(self):
        root = self.mk("loose")
        # mk() 登记过；这里换成「目录在、台账里没有」的真实情况
        targets.forget("loose")
        self.assertIsNone(targets.get(root))
        port = self.start_fixed(root)
        status, body = self.jcall(port, "/api/projects")
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 1)
        self.assertEqual(body["projects"][0]["alias"], os.path.basename(root))

        status, detail = self.jcall(port, "/api/projects/" + os.path.basename(root))
        self.assertEqual(status, 200)
        self.assertEqual(detail["stage"], "no_recon")

    def test_registered_workspace_keeps_its_ledger_alias(self):
        root = self.mk("named", eng="ENG-KEEP")
        port = self.start_fixed(root)
        status, body = self.jcall(port, "/api/projects")
        self.assertEqual(body["projects"][0]["alias"], "named")   # mk 登记的是 alias=named
        status, detail = self.jcall(port, "/api/projects/named")
        self.assertEqual(detail["project"]["engagement_id"], "ENG-KEEP")


class MiscTest(ApiProjectsCase):
    def test_jobs_endpoint(self):
        self.mk("one")
        port = self.start()
        status, body = self.jcall(port, "/api/jobs")
        self.assertEqual(status, 200)
        self.assertEqual(body["jobs"], [])
        status, body = self.jcall(port, "/api/jobs?project=one")
        self.assertEqual(body["jobs"], [])

    def test_static_shell_is_served(self):
        port = self.start()
        status, body = self.call(port, "/")
        self.assertEqual(status, 200)
        html = body.decode("utf-8")
        self.assertIn("view-projects", html)
        self.assertIn("identity-dialog", html)

        status, body = self.call(port, "/ui/app.js")
        self.assertEqual(status, 200)
        self.assertIn("loadProjects", body.decode("utf-8"))

        status, body = self.call(port, "/ui/style.css")
        self.assertEqual(status, 200)
        self.assertIn("pcard", body.decode("utf-8"))

    def test_traversal_still_blocked(self):
        port = self.start()
        status, _ = self.call(port, "/ui/../api.py")
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
