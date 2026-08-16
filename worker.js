/**
 * CI/CD Container Release Gate
 * POST /release-gate
 *
 * Reads a CI-run description and returns:
 *   {"decision":"promote"|"block", "violations":["CODE", ...]}
 */

const REQUIRED_PERMISSIONS = {
  contents: "read",
  packages: "write",
  "id-token": "none",
};

const SHA_RE = /^[0-9a-f]{40}$/;

function checkPermissions(permissions) {
  if (!permissions || typeof permissions !== "object") return false;
  const keys = Object.keys(permissions);
  if (keys.length !== 3) return false;
  for (const [k, v] of Object.entries(REQUIRED_PERMISSIONS)) {
    if (permissions[k] !== v) return false;
  }
  return true;
}

function checkActionsPinned(actions) {
  if (!Array.isArray(actions)) return true; // nothing to fail on
  for (const action of actions) {
    if (!action) continue;
    if (action.owner === "actions") continue; // tag allowed
    if (!SHA_RE.test(String(action.ref || ""))) {
      return false; // found an unpinned third-party action
    }
  }
  return true;
}

function evaluate(payload) {
  const violations = [];

  const target = payload?.target;
  const event = payload?.event;
  const ref = payload?.ref;
  const workflow = payload?.workflow || {};
  const image = payload?.image || {};

  // 1. Least-privilege permissions
  if (!checkPermissions(workflow.permissions)) {
    violations.push("EXCESS_PERMISSION");
  }

  // 2. PR safety: never pull_request_target
  if (workflow.trigger === "pull_request_target") {
    violations.push("UNSAFE_PR_TRIGGER");
  }

  // 3. Tests must fully pass
  if (
    workflow.testsPassed !== true ||
    workflow.matrixComplete !== true ||
    workflow.failFast !== false
  ) {
    violations.push("TESTS_INCOMPLETE");
  }

  // 4. Action pinning
  if (!checkActionsPinned(workflow.actions)) {
    violations.push("MUTABLE_ACTION");
  }

  // 5. Image: multi-stage
  if (image.multiStage !== true) {
    violations.push("SINGLE_STAGE_IMAGE");
  }

  // 6. Image: non-root
  if (image.runsAsRoot !== false) {
    violations.push("ROOT_RUNTIME");
  }

  // 7. Image: safe secret handling
  if (image.secretMode !== "none" && image.secretMode !== "buildkit") {
    violations.push("SECRET_IN_LAYER");
  }

  // 8. Image: zero critical CVEs
  if (!(Number(image.criticalVulnerabilities) === 0)) {
    violations.push("CRITICAL_CVE");
  }

  // 9. Image: pinned by digest
  if (image.digestPinned !== true) {
    violations.push("UNPINNED_IMAGE");
  }

  // 10 & 11. Production-only extra requirements
  if (target === "production") {
    if (!(event === "push" && ref === "refs/heads/main")) {
      violations.push("INVALID_PRODUCTION_REF");
    }
    if (workflow.environmentApproval !== true) {
      violations.push("APPROVAL_REQUIRED");
    }
  }

  return {
    decision: violations.length === 0 ? "promote" : "block",
    violations,
  };
}

export default {
  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === "/release-gate" && request.method === "POST") {
      let payload;
      try {
        payload = await request.json();
      } catch (e) {
        return new Response(
          JSON.stringify({ decision: "block", violations: ["INVALID_PAYLOAD"] }),
          { status: 400, headers: { "content-type": "application/json" } }
        );
      }

      const result = evaluate(payload);
      return new Response(JSON.stringify(result), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }

    return new Response("Not found", { status: 404 });
  },
};
