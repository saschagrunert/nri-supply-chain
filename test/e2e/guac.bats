#!/usr/bin/env bats

load helpers

GUAC_MOCK_PORT="${GUAC_MOCK_PORT:-9876}"
GUAC_MOCK_PID_FILE="${BATS_FILE_TMPDIR}/guac-mock.pid"

start_guac_mock() {
	local script="${BATS_FILE_TMPDIR}/guac_mock.py"
	cat >"$script" <<-'PYEOF'
		import http.server
		import json
		import sys

		class Handler(http.server.BaseHTTPRequestHandler):
		    def log_message(self, fmt, *args):
		        pass

		    def do_GET(self):
		        if self.path == "/healthz":
		            self.send_response(200)
		            self.send_header("Content-Type", "application/json")
		            self.end_headers()
		            self.wfile.write(b'{"status":"ok"}')
		            return

		        if self.path.startswith("/query/vulnerabilities"):
		            resp = {
		                "vulnerabilities": [
		                    {
		                        "package": self._param("digest"),
		                        "vulnerability": {
		                            "type": "osv",
		                            "vulnerabilityIDs": ["CVE-2024-0001"]
		                        }
		                    },
		                    {
		                        "package": "pkg:npm/transitive-dep@1.0",
		                        "vulnerability": {
		                            "type": "osv",
		                            "vulnerabilityIDs": ["CVE-2024-9999"]
		                        }
		                    }
		                ]
		            }
		            self._json_response(resp)
		            return

		        if self.path.startswith("/query/dependencies"):
		            resp = {"purls": ["pkg:npm/dep-a@1.0", "pkg:npm/dep-b@2.0", "pkg:npm/dep-c@3.0"]}
		            self._json_response(resp)
		            return

		        self.send_error(404)

		    def do_POST(self):
		        if self.path == "/query":
		            resp = {
		                "data": {
		                    "scorecards": [
		                        {
		                            "source": {"type": "git", "namespace": "github.com/test", "name": "repo"},
		                            "scorecard": {
		                                "aggregateScore": 7.5,
		                                "checks": [
		                                    {"check": "Code-Review", "score": 8},
		                                    {"check": "Maintained", "score": 9}
		                                ]
		                            }
		                        }
		                    ]
		                }
		            }
		            self._json_response(resp)
		            return
		        self.send_error(404)

		    def _param(self, key):
		        from urllib.parse import urlparse, parse_qs
		        return parse_qs(urlparse(self.path).query).get(key, [""])[0]

		    def _json_response(self, data):
		        body = json.dumps(data).encode()
		        self.send_response(200)
		        self.send_header("Content-Type", "application/json")
		        self.send_header("Content-Length", str(len(body)))
		        self.end_headers()
		        self.wfile.write(body)

		port = int(sys.argv[1])
		server = http.server.HTTPServer(("127.0.0.1", port), Handler)
		server.serve_forever()
	PYEOF

	python3 "$script" "$GUAC_MOCK_PORT" &
	echo $! >"$GUAC_MOCK_PID_FILE"

	local start_time
	start_time=$(date +%s)
	while (($(date +%s) - start_time < 10)); do
		if curl -sf --max-time 2 "http://127.0.0.1:${GUAC_MOCK_PORT}/healthz" >/dev/null 2>&1; then
			return 0
		fi
		sleep 0.5
	done
	echo "ERROR: GUAC mock server not ready on port $GUAC_MOCK_PORT after 10s" >&2
	return 1
}

stop_guac_mock() {
	stop_process_from_pidfile "$GUAC_MOCK_PID_FILE" "guac-mock"
}

write_plugin_config_guac() {
	local mode="$1"
	local fallback="${2:-warn}"
	cat >"$PLUGIN_CONFIG" <<-EOF
		verification = "${mode}"
		policy_dir = "${POLICY_DIR}"
		fetch_timeout = "30s"
		fetch_failure_policy = "allow"
		cache_ttl = "0s"
		cache_failure_ttl = "0s"
		metrics_addr = ":9090"

		[guac]
		endpoint = "http://127.0.0.1:${GUAC_MOCK_PORT}"
		timeout = "5s"
		fallback_policy = "${fallback}"
		checks = ["certify_vuln", "certify_scorecard", "is_dependency"]
		max_dependencies = 10
	EOF
}

write_plugin_config_guac_unreachable() {
	local mode="$1"
	local fallback="${2:-warn}"
	cat >"$PLUGIN_CONFIG" <<-EOF
		verification = "${mode}"
		policy_dir = "${POLICY_DIR}"
		fetch_timeout = "30s"
		fetch_failure_policy = "allow"
		cache_ttl = "0s"
		cache_failure_ttl = "0s"
		metrics_addr = ":9090"

		[guac]
		endpoint = "https://127.0.0.1:1"
		timeout = "1s"
		fallback_policy = "${fallback}"
		checks = ["certify_vuln"]
		max_dependencies = 5
	EOF
}

setup_file() {
	mkdir -p "$KUBERNIX_ROOT" "$POLICY_DIR"

	cat >"$POLICY_DIR/default.json" <<-'EOF'
		{
		  "slsa": {"missingPolicy": "allow"},
		  "vex": {"missingPolicy": "allow"}
		}
	EOF

	start_guac_mock
	start_kubernix_with_retry --log-level debug

	write_plugin_config_guac "warn"
	start_plugin
}

teardown_file() {
	stop_plugin
	stop_guac_mock
	stop_kubernix
}

@test "guac: queries run and produce audit log entries" {
	run_pod "guac-audit" "$PAUSE_IMAGE"
	wait_for_pod_status "guac-audit" "Running"
	assert_log_contains "GUAC"
}

@test "guac: vulnerability data appears in audit log" {
	run_pod "guac-vulns" "$PAUSE_IMAGE"
	wait_for_pod_status "guac-vulns" "Running"
	assert_log_contains "direct vulns"
}

@test "guac: guac_query_duration metric recorded" {
	run_pod "guac-metric" "$PAUSE_IMAGE"
	wait_for_pod_status "guac-metric" "Running"
	wait_for_metrics 'nri_supply_chain_guac_query_duration_seconds'

	run curl_metrics
	[[ "$status" -eq 0 ]]
	echo "$output" | grep -q 'nri_supply_chain_guac_query_duration_seconds'
}

@test "guac: fallback_policy warn allows pod when GUAC unreachable" {
	stop_plugin
	write_plugin_config_guac_unreachable "warn" "warn"
	start_plugin

	run_pod "guac-fb-warn" "$PAUSE_IMAGE"
	wait_for_pod_status "guac-fb-warn" "Running"
	assert_log_contains "GUAC query failed"

	stop_plugin
	write_plugin_config_guac "warn"
	start_plugin
}

@test "guac: fallback_policy allow skips GUAC silently" {
	stop_plugin
	write_plugin_config_guac_unreachable "warn" "allow"
	start_plugin

	run_pod "guac-fb-allow" "$PAUSE_IMAGE"
	wait_for_pod_status "guac-fb-allow" "Running"

	stop_plugin
	write_plugin_config_guac "warn"
	start_plugin
}

@test "guac: fallback_policy deny rejects pod when GUAC unreachable" {
	stop_plugin
	write_plugin_config_guac_unreachable "enforce" "deny"
	start_plugin

	run_pod "guac-fb-deny" "$PAUSE_IMAGE" || true
	assert_log_contains "Container rejected"

	stop_plugin
	write_plugin_config_guac "warn"
	start_plugin
}

@test "guac: config reload with GUAC endpoint change" {
	stop_plugin
	write_plugin_config_guac "warn"
	start_plugin

	run_pod "guac-reload-before" "$PAUSE_IMAGE"
	wait_for_pod_status "guac-reload-before" "Running"
	assert_log_contains "GUAC"

	write_plugin_config_guac_unreachable "warn" "warn"
	reload_plugin
	assert_log_contains "Config reloaded successfully"

	run_pod "guac-reload-after" "$PAUSE_IMAGE"
	wait_for_pod_status "guac-reload-after" "Running"
	assert_log_contains "GUAC query failed"

	stop_plugin
	write_plugin_config_guac "warn"
	start_plugin
}

@test "guac: disabling GUAC via config reload removes guac check" {
	stop_plugin
	write_plugin_config_guac "warn"
	start_plugin

	run_pod "guac-disable-before" "$PAUSE_IMAGE"
	wait_for_pod_status "guac-disable-before" "Running"

	write_plugin_config "warn"
	reload_plugin
	assert_log_contains "Config reloaded successfully"

	# shellcheck disable=SC2034
	LOG_OFFSET=$(wc -c <"$PLUGIN_LOG")

	run_pod "guac-disable-after" "$PAUSE_IMAGE"
	wait_for_pod_status "guac-disable-after" "Running"
	assert_log_contains "Supply chain audit"

	run ! plugin_log_contains "GUAC"

	stop_plugin
	write_plugin_config_guac "warn"
	start_plugin
}

@test "guac: enabling GUAC via config reload activates guac check" {
	stop_plugin
	write_plugin_config "warn"
	start_plugin

	# shellcheck disable=SC2034
	LOG_OFFSET=$(wc -c <"$PLUGIN_LOG")

	run_pod "guac-enable-before" "$PAUSE_IMAGE"
	wait_for_pod_status "guac-enable-before" "Running"
	assert_log_contains "Supply chain audit"
	run ! plugin_log_contains "GUAC"

	write_plugin_config_guac "warn"
	reload_plugin
	assert_log_contains "Config reloaded successfully"

	# shellcheck disable=SC2034
	LOG_OFFSET=$(wc -c <"$PLUGIN_LOG")

	run_pod "guac-enable-after" "$PAUSE_IMAGE"
	wait_for_pod_status "guac-enable-after" "Running"
	assert_log_contains "GUAC"

	stop_plugin
	write_plugin_config_guac "warn"
	start_plugin
}

@test "guac: scorecard resolved logged at debug level" {
	run_pod "guac-scorecard" "$PAUSE_IMAGE"
	wait_for_pod_status "guac-scorecard" "Running"
	assert_log_contains "GUAC scorecard resolved"
}
